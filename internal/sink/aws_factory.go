package sink

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// NewSecretsManagerClientFactory returns a factory that loads credentials from
// the default AWS chain (on EKS: IRSA or Pod Identity) and caches one client
// per region for the life of the process.
func NewSecretsManagerClientFactory() SecretsManagerClientFactory {
	var (
		mu      sync.Mutex
		clients = map[string]SecretsManagerAPI{}
	)
	return func(ctx context.Context, region string) (SecretsManagerAPI, error) {
		mu.Lock()
		defer mu.Unlock()
		if c, ok := clients[region]; ok {
			return c, nil
		}
		var opts []func(*config.LoadOptions) error
		if region != "" {
			opts = append(opts, config.WithRegion(region))
		}
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, err
		}
		c := secretsmanager.NewFromConfig(cfg)
		clients[region] = c
		return c, nil
	}
}
