package sink

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// fakeSM is an in-memory Secrets Manager that honours ClientRequestToken
// idempotency the same way the real service does.
type fakeSM struct {
	secrets map[string][]string        // id -> version payloads
	tokens  map[string]map[string]bool // id -> seen tokens
	putErr  error
}

func newFakeSM() *fakeSM {
	return &fakeSM{secrets: map[string][]string{}, tokens: map[string]map[string]bool{}}
}

func (f *fakeSM) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	id := aws.ToString(in.SecretId)
	if _, ok := f.secrets[id]; !ok {
		return nil, &smtypes.ResourceNotFoundException{Message: aws.String("not found")}
	}
	if f.tokens[id][aws.ToString(in.ClientRequestToken)] {
		return &secretsmanager.PutSecretValueOutput{}, nil
	}
	f.tokens[id][aws.ToString(in.ClientRequestToken)] = true
	f.secrets[id] = append(f.secrets[id], aws.ToString(in.SecretString))
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeSM) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	id := aws.ToString(in.Name)
	f.secrets[id] = []string{aws.ToString(in.SecretString)}
	f.tokens[id] = map[string]bool{aws.ToString(in.ClientRequestToken): true}
	return &secretsmanager.CreateSecretOutput{}, nil
}

func TestPushCreatesThenUpdates(t *testing.T) {
	sm := newFakeSM()
	s := &AWSSecretsManager{Client: sm, SecretID: "prod/db"}
	ctx := context.Background()
	uid := "6f1c2c3e-0000-4000-8000-000000000001"

	if err := s.Push(ctx, PushRequest{OwnerUID: uid, Version: 1, Data: map[string][]byte{"password": []byte("a")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Push(ctx, PushRequest{OwnerUID: uid, Version: 2, Data: map[string][]byte{"password": []byte("b")}}); err != nil {
		t.Fatal(err)
	}
	if got := len(sm.secrets["prod/db"]); got != 2 {
		t.Fatalf("expected 2 versions, got %d", got)
	}
	var latest map[string]string
	if err := json.Unmarshal([]byte(sm.secrets["prod/db"][1]), &latest); err != nil {
		t.Fatal(err)
	}
	if latest["password"] != "b" {
		t.Fatalf("latest password = %q", latest["password"])
	}
}

func TestPushIsIdempotent(t *testing.T) {
	sm := newFakeSM()
	s := &AWSSecretsManager{Client: sm, SecretID: "prod/db"}
	req := PushRequest{OwnerUID: "6f1c2c3e-0000-4000-8000-000000000001", Version: 1, Data: map[string][]byte{"k": []byte("v")}}
	for range 3 {
		if err := s.Push(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(sm.secrets["prod/db"]); got != 1 {
		t.Fatalf("retries created %d versions, want 1", got)
	}
}

func TestPushPropagatesErrors(t *testing.T) {
	sm := newFakeSM()
	sm.putErr = errors.New("throttled")
	s := &AWSSecretsManager{Client: sm, SecretID: "x"}
	if err := s.Push(context.Background(), PushRequest{OwnerUID: "u", Version: 1}); err == nil {
		t.Fatal("expected error")
	}
}

func TestClientRequestTokenLength(t *testing.T) {
	for _, uid := range []string{"short", "6f1c2c3e-0000-4000-8000-000000000001", string(make([]byte, 100))} {
		tok := ClientRequestToken(uid, 12345)
		if len(tok) < 32 || len(tok) > 64 {
			t.Errorf("token %q has length %d", tok, len(tok))
		}
	}
	if ClientRequestToken("a", 1) == ClientRequestToken("a", 2) {
		t.Error("tokens for different versions must differ")
	}
}
