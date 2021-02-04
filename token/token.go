package token

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/vmihailenco/msgpack/v4"
)

type Print func(string, ...interface{})

func debug(printFunc Print, format string, args ...interface{}) {
	if len(args) == 0 {
		return
	}

	if v, ok := args[0].(string); ok && v == "" {
		// skip empty strings
		return
	}

	if v, ok := args[0].([]string); ok && len(v) == 0 {
		// skip empty strings
		return
	}

	if len(args) > 1 {
		printFunc(format+"\n", args...)
		return
	}

	printFunc(format+"\n", args[0])
}

// PrettyPrint prints token details
func PrettyPrint(printFunc Print, t Token, authMethods map[int]string, sortedKeys []int) {
	if t == nil {
		return
	}

	am := t.GetAuthMethods()

	debug(printFunc, "Type: %s", t.GetType().String())
	debug(printFunc, "UserID: %s", t.GetUserID())
	debug(printFunc, "AuthMethods: %d %q", am, am.Decode(authMethods, sortedKeys))
	debug(printFunc, "ProjectID: %s", t.GetProjectID())
	debug(printFunc, "DomainID: %s", t.GetDomainID())

	debug(printFunc, "TrustID: %s", t.GetTrustID())
	debug(printFunc, "AccessTokenID: %s", t.GetAccessTokenID())
	debug(printFunc, "SystemID: %s", t.GetSystemID())
	debug(printFunc, "AppCredID: %s", t.GetAppCredID())

	// federated
	debug(printFunc, "GroupIDs: %s", t.GetFederatedGroupIDs())
	debug(printFunc, "IdPID: %s", t.GetIdPID())
	debug(printFunc, "ProtocolID: %s", t.GetProtocolID())

	debug(printFunc, "ExpiresAt: %s", t.GetExpiresAt())
	debug(printFunc, "ExpiresIn: %s", time.Until(t.GetExpiresAt()))
	debug(printFunc, "AuditIDs: %q", t.GetAuditIDs())
}

// GenerateAuthMethodsMapList generates a special map and list from an ordered
// list of supported auth methods. They allow to identify a list of auth methods
// used to generate the token. The auth list and its order must correspond to a
// keystone configuration.
func GenerateAuthMethodsMapList(authMethods []string) (map[int]string, []int) {
	ret := make(map[int]string, len(authMethods))
	keys := make([]int, len(authMethods))

	ind := 1
	for i, authMethod := range authMethods {
		ret[ind] = authMethod
		keys[i] = ind
		ind = ind * 2
	}
	sort.Sort(sort.Reverse(sort.IntSlice(keys)))

	return ret, keys
}

// Encode encodes and signs with a key an OpenStack token according to passed
// token format.
func Encode(token Token, key *fernet.Key) (*string, error) {
	b, err := msgpack.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal msgpack: %s", err)
	}

	v, err := fernet.EncryptAndSign(b, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt and sign the fernet token: %s", err)
	}

	t := strings.TrimRight(string(v), "=")

	return &t, nil
}

// Decode verifies and decodes an OpenStack token using a list of Fernet secret
// keys. TTL is a maximum duration during which a token is valid.
func Decode(token string, ttl time.Duration, keys []*fernet.Key, extra ...bool) (Token, error) {
	// check the token padding and length
	if v, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		return nil, err
	} else if l := len(v); l <= 8 {
		return nil, fmt.Errorf("fernet token size (%d) is too small", l)
	} else {
		// reencode with a padding
		token = base64.URLEncoding.EncodeToString(v)
	}

	msg := fernet.VerifyAndDecrypt([]byte(token), ttl, keys)
	if msg == nil {
		return nil, fmt.Errorf("fernet token verification and decryption failed")
	}

	switch len(extra) {
	case 1:
		return unmarshalMsg(msg, extra[0], false)
	case 2:
		return unmarshalMsg(msg, extra[0], extra[1])
	}

	return unmarshalMsg(msg, false, false)
}

func unmarshalMsg(msg []byte, allowExpired bool, debug bool) (Token, error) {
	if debug {
		var tmp []interface{}
		err := msgpack.Unmarshal(msg, &tmp)
		if err != nil {
			return nil, err
		}
		if len(tmp) > 0 {
			fmt.Printf("Version: %d\n", tmp[0])
			for i, v := range tmp[1:] {
				fmt.Printf("%d: %+#v\n", i+1, v)
			}
		}
	}

	var v struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
	}
	err := msgpack.Unmarshal(msg, &v)
	if err != nil {
		return nil, err
	}

	var t Token
	switch v.Version {
	case Unscoped:
		t = &UnscopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case DomainScoped:
		t = &DomainScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case ProjectScoped:
		t = &ProjectScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case TrustScoped:
		t = &TrustScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case FederatedUnscoped:
		t = &FederatedUnscopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case FederatedProjectScoped:
		t = &FederatedProjectScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case FederatedDomainScoped:
		t = &FederatedDomainScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case OAuthScoped:
		t = &OAuthScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case SystemScoped:
		t = &SystemScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	case ApplicationCredentialScoped:
		t = &ApplicationCredentialScopedToken{}
		err = msgpack.Unmarshal(msg, t)
	default:
		return nil, fmt.Errorf("%d version is unsupported", v.Version)
	}

	if err != nil {
		return nil, err
	}

	if !allowExpired && time.Until(t.GetExpiresAt()) < 0 {
		return t, fmt.Errorf("token expired %s", t.GetExpiresAt())
	}

	return t, nil
}
