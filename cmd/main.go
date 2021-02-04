package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
	"gopkg.in/yaml.v2"

	"github.com/kayrus/openstack-token/token"
)

type Config struct {
	TokenTTL    time.Duration  `yaml:"-"`
	FernetKeys  []*fernet.Key  `yaml:"-"`
	AuthMethods map[int]string `yaml:"-"`
	AuthIndexes []int          `yaml:"-"`
}

type args struct {
	configFile   string
	userID       string
	userName     string
	userDomainID string
	projectID    string
	authMethod   uint
	generateKey  bool
}

func (r *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type tmp Config
	var s struct {
		tmp
		TokenTTL    string   `yaml:"tokenTTL"`
		FernetKeys  []string `yaml:"fernetKeys"`
		AuthMethods []string `yaml:"authMethods"`
	}

	if err := unmarshal(&s.tmp); err != nil {
		return err
	}

	if err := unmarshal(&s); err != nil {
		return err
	}

	*r = Config(s.tmp)

	tokenTTL, err := time.ParseDuration(s.TokenTTL)
	if err != nil {
		return err
	}
	if tokenTTL <= 0 {
		return fmt.Errorf("tokenTTL must be greater than zero")
	}
	r.TokenTTL = tokenTTL

	for _, key := range s.FernetKeys {
		key, err := fernet.DecodeKey(key)
		if err != nil {
			return err
		}
		r.FernetKeys = append(r.FernetKeys, key)
	}
	if len(r.FernetKeys) == 0 {
		return fmt.Errorf("fernetKeys cannot be empty")
	}

	r.AuthMethods, r.AuthIndexes = token.GenerateAuthMethodsMapList(s.AuthMethods)

	return nil
}

func readConfig(filename string) (*Config, error) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err = yaml.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("cannot parse %q file: %w", filename, err)
	}

	return &config, nil
}

func printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func parseToken(tok string, cfg *Config) error {
	// decode OpenStack Fernet token
	t, err := token.Decode(tok, cfg.TokenTTL, cfg.FernetKeys)
	if err != nil {
		// detect expired token
		if t, err := token.Decode(tok, cfg.TokenTTL*99999, cfg.FernetKeys); err != nil {
			token.PrettyPrint(printf, t, cfg.AuthMethods, cfg.AuthIndexes)
			return err
		}
		return err
	}

	token.PrettyPrint(printf, t, cfg.AuthMethods, cfg.AuthIndexes)

	return nil
}

func generateToken(args *args, cfg *Config) (*string, error) {
	// generate new token to be valid for config.TokenTTL duration
	timeNext := time.Now().Add(cfg.TokenTTL)
	auditID := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(auditID)

	var genToken token.Token
	if args.projectID != "" {
		projectID, err := hex.DecodeString(args.projectID)
		if err != nil {
			return nil, err
		}

		genToken = &token.ProjectScopedToken{
			UserID: token.Data{
				Value: args.userID,
			},
			AuthMethods: token.AuthMethods(args.authMethod),
			ProjectID: token.Data{
				Bytes: true,
				Value: string(projectID),
			},
			ExpiresAt: float64(timeNext.Unix()),
			AuditIDs:  []token.Hex{token.Hex(auditID)},
		}
	} else if args.userID != "" {
		genToken = &token.UnscopedToken{
			UserID: token.Data{
				Value: args.userID,
			},
			AuthMethods: token.AuthMethods(args.authMethod),
			ExpiresAt:   float64(timeNext.Unix()),
			AuditIDs:    []token.Hex{token.Hex(auditID)},
		}
	} else if args.userName != "" {
		if args.userDomainID == "" {
			return nil, fmt.Errorf("--user-domain-id is required, when --user-name is used")
		}

		_, err := hex.DecodeString(args.userDomainID)
		if err != nil {
			return nil, fmt.Errorf("--user-domain-id is invalid: %w", err)
		}

		uid := sha256.Sum256([]byte(fmt.Sprintf("%suser%s", args.userDomainID, strings.ToUpper(args.userName))))
		userID := hex.EncodeToString(uid[:])
		genToken = &token.UnscopedToken{
			UserID: token.Data{
				Value: userID,
			},
			AuthMethods: token.AuthMethods(args.authMethod),
			ExpiresAt:   float64(timeNext.Unix()),
			AuditIDs:    []token.Hex{token.Hex(auditID)},
		}
	} else {
		return nil, fmt.Errorf("not enough parameters, see help")
	}

	return token.Encode(genToken, cfg.FernetKeys[0])
}

func main() {
	args := &args{}

	flag.StringVar(&args.configFile, "config", "config.yaml", "config file path")
	flag.StringVar(&args.userID, "user-id", os.Getenv("OS_USER_ID"), "OpenStack user ID to generate the project scoped token")
	flag.StringVar(&args.userName, "user-name", os.Getenv("OS_USER_NAME"), "OpenStack user name to generate the unscoped token (works only with AD/LDAP users, requires user domain ID)")
	flag.StringVar(&args.userDomainID, "user-domain-id", os.Getenv("OS_USER_DOMAIN_ID"), "OpenStack user's domain ID to generate the unscoped token (works only with AD/LDAP users)")
	flag.StringVar(&args.projectID, "project-id", os.Getenv("OS_PROJECT_ID"), "OpenStack project ID to generate the project scoped token")
	flag.UintVar(&args.authMethod, "auth-method", 1, "Auth method number to use in a generated token (max 127)")
	flag.BoolVar(&args.generateKey, "generate-key", false, "Generate a Fernet key and exit")
	flag.Parse()

	if args.generateKey {
		key := &fernet.Key{}
		err := key.Generate()
		if err != nil {
			log.Fatalf("failed to generate a Fernet key: %s", err)
		}
		fmt.Printf("Generated key: %s\n", key.Encode())
		return
	}

	if args.configFile == "" {
		log.Print(`Config path is empty, using default "config.yaml"`)
		args.configFile = "config.yaml"
	}

	if args.authMethod > 127 {
		log.Fatal("max auth must not exceed 127")
	}

	cfg, err := readConfig(args.configFile)
	if err != nil {
		log.Fatal(err)
	}

	if tok := os.Getenv("OS_AUTH_TOKEN"); tok != "" {
		// decode token only
		err = parseToken(tok, cfg)
		if err != nil {
			log.Fatalf("Failed to verify the token: %v", err)
		}
		return
	}

	// generate new token to be valid for config.TokenTTL duration
	tok, err := generateToken(args, cfg)
	if err != nil {
		log.Fatal(err)
	}

	// verify the generated token
	err = parseToken(*tok, cfg)
	if err != nil {
		log.Fatalf("Failed to verify the generated token: %v", err)
	}

	fmt.Printf("Generated token: %s\n", *tok)
}
