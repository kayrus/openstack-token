package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
	"gopkg.in/yaml.v3"

	"github.com/kayrus/openstack-token/token"
	"github.com/kayrus/openstack-token/vault"
)

const timeFormat = "2006-01-02 15:04:05.999999999 -0700 MST"

type Config struct {
	TokenTTL    time.Duration  `yaml:"-"`
	FernetKeys  []*fernet.Key  `yaml:"-"`
	AuthMethods map[int]string `yaml:"-"`
	AuthIndexes []int          `yaml:"-"`
}

type auditID []string

func (a *auditID) String() string {
	return strings.Join(*a, " ")
}

func (a *auditID) Set(value string) error {
	v, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	*a = append(*a, string(v))
	return nil
}

type args struct {
	configFile   string
	userID       string
	userName     string
	userDomainID string
	projectID    string
	domainID     string
	appCredID    string
	authMethod   uint
	generateKey  bool
	auditIDs     auditID
	expiresAt    time.Time
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

	store := make(map[string]*vault.Store)
	for _, v := range s.FernetKeys {
		key, err := fernet.DecodeKey(v)
		if err != nil {
			key, err = vault.URLToToken(store, v)
			if err != nil {
				return err
			}
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
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read cfg file: %w", err)
	}

	var cfg Config
	if err = yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("cannot parse %q file: %w", filename, err)
	}

	return &cfg, nil
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

func resolveUserID(userName string, domainID string) (string, error) {
	if userName == "" {
		return "", fmt.Errorf("-user-name is empty")
	}

	if domainID == "" {
		return "", fmt.Errorf("-user-domain-id is required, when -user-name is used")
	}

	uid := sha256.Sum256([]byte(fmt.Sprintf("%suser%s", domainID, strings.ToUpper(userName))))
	return hex.EncodeToString(uid[:]), nil
}

func generateToken(args *args, cfg *Config) (*string, error) {
	// generate new token to be valid for config.TokenTTL duration
	timeNext := time.Now().Add(cfg.TokenTTL)
	if !args.expiresAt.IsZero() {
		timeNext = args.expiresAt
	}

	var auditIDs []token.Hex
	if len(args.auditIDs) > 0 {
		auditIDs = make([]token.Hex, len(args.auditIDs))
		for i, v := range args.auditIDs {
			auditIDs[i] = token.Hex(v)
		}
	} else {
		auditID := make([]byte, 16)
		rand := rand.New(rand.NewSource(time.Now().UnixNano()))
		rand.Read(auditID)
		auditIDs = []token.Hex{token.Hex(auditID)}
	}

	var err error
	userID := args.userID
	if userID == "" {
		userID, err = resolveUserID(args.userName, args.userDomainID)
		if err != nil {
			return nil, err
		}
	}

	var genToken token.Token
	if args.appCredID != "" {
		if args.projectID == "" {
			return nil, fmt.Errorf("-project-id and -auth-method greater than 1 are required for application credential scoped token")
		}

		if cfg.AuthMethods[int(args.authMethod)] != "application_credential" {
			return nil, fmt.Errorf("-auth-method=%d doesn't correspond to application credential auth method, decoded methods: %v", args.authMethod, cfg.AuthMethods)
		}

		projectID, err := hex.DecodeString(args.projectID)
		if err != nil {
			return nil, err
		}
		appCredID, err := hex.DecodeString(args.appCredID)
		if err != nil {
			return nil, err
		}

		genToken = &token.ApplicationCredentialScopedToken{
			UserID: token.Data{
				Value: userID,
			},
			AuthMethods: token.AuthMethods(args.authMethod),
			ProjectID: token.Data{
				Bytes: true,
				Value: string(projectID),
			},
			AppCredID: token.Data{
				Bytes: true,
				Value: string(appCredID),
			},
			ExpiresAt: float64(timeNext.Unix()),
			AuditIDs:  auditIDs,
		}
	} else if args.projectID != "" {
		projectID, err := hex.DecodeString(args.projectID)
		if err != nil {
			return nil, err
		}

		genToken = &token.ProjectScopedToken{
			UserID: token.Data{
				Value: userID,
			},
			AuthMethods: token.AuthMethods(args.authMethod),
			ProjectID: token.Data{
				Bytes: true,
				Value: string(projectID),
			},
			ExpiresAt: float64(timeNext.Unix()),
			AuditIDs:  auditIDs,
		}
	} else if args.domainID != "" {
		domainID, err := hex.DecodeString(args.domainID)
		if err != nil {
			// domain is a string, e.g. "default"
			domainID = []byte(args.domainID)
		}
		genToken = &token.DomainScopedToken{
			UserID: token.Data{
				Value: userID,
			},
			DomainID:    token.Hex(domainID),
			AuthMethods: token.AuthMethods(args.authMethod),
			ExpiresAt:   float64(timeNext.Unix()),
			AuditIDs:    auditIDs,
		}
	} else {
		genToken = &token.UnscopedToken{
			UserID: token.Data{
				Value: userID,
			},
			AuthMethods: token.AuthMethods(args.authMethod),
			ExpiresAt:   float64(timeNext.Unix()),
			AuditIDs:    auditIDs,
		}
	}

	return token.Encode(genToken, cfg.FernetKeys[0])
}

func main() {
	args := &args{}
	var expiresAt string

	flag.StringVar(&args.configFile, "config", "config.yaml", "config file path")
	flag.StringVar(&args.userID, "user-id", os.Getenv("OS_USER_ID"), "OpenStack user ID to generate the project scoped token")
	flag.StringVar(&args.userName, "user-name", os.Getenv("OS_USER_NAME"), "OpenStack user name to generate the unscoped token (works only with AD/LDAP users, requires user domain ID)")
	flag.StringVar(&args.userDomainID, "user-domain-id", os.Getenv("OS_USER_DOMAIN_ID"), "OpenStack user's domain ID to generate the unscoped token (works only with AD/LDAP users)")
	flag.StringVar(&args.projectID, "project-id", os.Getenv("OS_PROJECT_ID"), "OpenStack project ID to generate the project scoped token")
	flag.StringVar(&args.domainID, "domain-id", os.Getenv("OS_DOMAIN_ID"), "OpenStack domain ID to generate the domain scoped token")
	flag.StringVar(&args.appCredID, "application-credential-id", os.Getenv("OS_APPLICATION_CREDENTIAL_ID"), "OpenStack application credential ID to generate the application credential scoped token")
	flag.StringVar(&expiresAt, "expires-at", "", fmt.Sprintf("override token expiration date (%q format)", timeFormat))
	flag.Var(&args.auditIDs, "audit-id", "Custom audit ID for the token (can be specified multiple times)")
	flag.UintVar(&args.authMethod, "auth-method", 1, "Auth method number to use in a generated token (max 127)")
	flag.BoolVar(&args.generateKey, "generate-key", false, "Generate a Fernet key and exit")
	flag.Parse()

	if expiresAt != "" {
		var err error
		args.expiresAt, err = time.Parse(timeFormat, expiresAt)
		if err != nil {
			log.Fatalf("failed to parse expiration date: %v", err)
		}
	}

	if args.generateKey {
		key := &fernet.Key{}
		err := key.Generate()
		if err != nil {
			log.Fatalf("failed to generate a Fernet key: %v", err)
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
