package vault

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fernet/fernet-go"

	vaultapi "github.com/hashicorp/vault/api"
)

type Store struct {
	client     *vaultapi.Client
	engineName string
}

func NewStoreFromEnvironment(addr, engine string) (*Store, error) {
	client, err := createClient(addr)
	return &Store{
		client:     client,
		engineName: engine,
	}, err
}

func URLToToken(vault map[string]*Store, addr string) (*fernet.Key, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(u.Path, "/")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid token URL: %s", addr)
	}
	// remove leading slash
	parts = parts[1:]

	vaultAddr := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	var engine string
	engine, parts = parts[0], parts[1:]
	vaultKey := fmt.Sprintf("%s%s", vaultAddr, engine)
	if vault[vaultKey] == nil {
		vault[vaultKey], err = NewStoreFromEnvironment(vaultAddr, engine)
		if err != nil {
			return nil, err
		}
	}

	key := parts[len(parts)-1]
	path := fmt.Sprintf("%s/data/%s", engine, strings.Join(parts[:len(parts)-1], "/"))
	tokenb64, err := vault[vaultKey].get(path, key)
	if err != nil {
		return nil, err
	}

	token, err := base64.StdEncoding.DecodeString(tokenb64)
	if err != nil {
		return nil, err
	}

	return fernet.DecodeKey(string(token))
}

func createClient(addr string) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("while reading Vault config from environment: %w", cfg.Error)
	}
	if addr != "" {
		cfg.Address = addr
	}

	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("while initializing Vault client: %w", err)
	}

	// fallback to ~/.vault-token
	if client.Token() == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("while fetching home directory: %w", err)
		}
		vaultTokenFile := homeDir + "/.vault-token"
		if _, err := os.Stat(vaultTokenFile); err == nil {
			bytes, err := os.ReadFile(vaultTokenFile)
			if err != nil {
				return nil, fmt.Errorf("failed reading %s: %w", vaultTokenFile, err)
			}
			client.SetToken(strings.TrimSpace(string(bytes)))
		}
	}

	if client.Token() == "" {
		return nil, fmt.Errorf("VAULT_TOKEN isn't set or vault cli is not logged in")
	}

	return client, nil
}

func (s *Store) find(path string) (map[string]interface{}, error) {
	secret, err := s.client.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found: %s", path)
	}

	metadata, ok := secret.Data["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("secret doesn't contain expected metadata")
	}
	deletionTime, ok := metadata["deletion_time"].(string)
	if ok {
		_, err = time.Parse(time.RFC3339Nano, deletionTime)
		if err == nil {
			return nil, fmt.Errorf("secret path marked deleted")
		}
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("secret doesn't contain expected data")
	}

	return data, nil
}

func (s *Store) get(path, key string) (string, error) {
	data, err := s.find(path)
	if err != nil {
		return "", err
	}

	value, exists := data[key]
	if !exists {
		return "", fmt.Errorf("key not found: %s/%s", path, key)
	}
	switch value := value.(type) {
	case string:
		return value, nil
	}

	return "", fmt.Errorf("key %q of secret %q has unusable data type %T", key, path, value)
}
