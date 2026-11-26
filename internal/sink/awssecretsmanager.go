package sink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// SecretsManagerAPI is the subset of the Secrets Manager client the sink uses.
// Narrowing the interface keeps tests free of AWS credentials and network.
type SecretsManagerAPI interface {
	PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	CreateSecret(ctx context.Context, in *secretsmanager.CreateSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
}

// SecretsManagerClientFactory returns a client for a region ("" = default).
type SecretsManagerClientFactory func(ctx context.Context, region string) (SecretsManagerAPI, error)

// AWSSecretsManager writes a Secret version to AWS Secrets Manager as a JSON
// object of string values.
type AWSSecretsManager struct {
	Client   SecretsManagerAPI
	SecretID string
}

var _ Sink = (*AWSSecretsManager)(nil)

// Name implements Sink.
func (s *AWSSecretsManager) Name() string { return "aws-secrets-manager" }

// Push implements Sink.
//
// Idempotency: Secrets Manager deduplicates writes by ClientRequestToken. The
// token is derived from the SecretRotation UID and version, so a retry of the
// same version is a no-op rather than a new AWS secret version.
func (s *AWSSecretsManager) Push(ctx context.Context, req PushRequest) error {
	payload := make(map[string]string, len(req.Data))
	for k, v := range req.Data {
		payload[k] = string(v)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding secret payload: %w", err)
	}
	token := ClientRequestToken(req.OwnerUID, req.Version)

	_, err = s.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:           aws.String(s.SecretID),
		SecretString:       aws.String(string(body)),
		ClientRequestToken: aws.String(token),
	})
	var notFound *smtypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		_, err = s.Client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:               aws.String(s.SecretID),
			SecretString:       aws.String(string(body)),
			ClientRequestToken: aws.String(token),
			Description:        aws.String("Managed by secret-rotation-operator"),
			Tags: []smtypes.Tag{
				{Key: aws.String("managed-by"), Value: aws.String("secret-rotation-operator")},
			},
		})
	}
	if err != nil {
		return fmt.Errorf("writing to Secrets Manager secret %q: %w", s.SecretID, err)
	}
	return nil
}

// ClientRequestToken builds a deterministic idempotency token. Secrets Manager
// requires 32-64 characters. The version is zero-padded to a fixed width (so
// distinct versions can never collide) and the UID — 36 characters for any
// real Kubernetes object — is clamped to keep the total within 64.
func ClientRequestToken(ownerUID string, version int64) string {
	const versionWidth, maxLen = 20, 64
	prefix := ownerUID
	if len(prefix) > maxLen-versionWidth-1 {
		prefix = prefix[:maxLen-versionWidth-1]
	}
	for len(prefix) < 11 { // 11 + 1 + 20 = 32, the service minimum
		prefix = "0" + prefix
	}
	return fmt.Sprintf("%s-%0*d", prefix, versionWidth, version)
}
