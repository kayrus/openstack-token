package testing

import (
	"flag"
	"reflect"
	"testing"

	"github.com/kayrus/openstack-token/token"
)

var (
	debug    bool
	matchErr = "tokens don't match, expected: %s, decoded: %s"
)

func init() {
	flag.BoolVar(&debug, "debug", false, "print verbose logs")
}

func TestExpiredFernetSignature(t *testing.T) {
	testToken := tokensToDecode["ExpiredToken"]

	decodedTok, err := token.Decode(testToken, ttl, fernetKeys, false, debug)
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if err == nil {
		t.Error("expected token to be expired")
	}
	t.Log(err)
}

func TestExpiredToken(t *testing.T) {
	testToken := tokensToDecode["UnscopedToken"]

	decodedTok, err := token.Decode(testToken, oneSecond, fernetKeys, false, debug)
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if err == nil {
		t.Error("expected token to be expired")
	}
	t.Log(err)
}

func TestUnscopedToken(t *testing.T) {
	testToken := tokensToEncode["UnscopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeUnscopedToken(tok, t)
}

func testDecodeUnscopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["UnscopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeUnscopedToken(t *testing.T) {
	testToken := tokensToDecode["UnscopedToken"]

	testDecodeUnscopedToken(&testToken, t)
}

func TestDomainScopedToken(t *testing.T) {
	testToken := tokensToEncode["DomainScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeDomainScopedToken(tok, t)
}

func testDecodeDomainScopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["DomainScopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeDomainScopedToken(t *testing.T) {
	testToken := tokensToDecode["DomainScopedToken"]

	testDecodeDomainScopedToken(&testToken, t)
}

func TestProjectScopedToken(t *testing.T) {
	testToken := tokensToEncode["ProjectScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeProjectScopedToken(tok, t)
}

func testDecodeProjectScopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["ProjectScopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeProjectScopedToken(t *testing.T) {
	testToken := tokensToDecode["ProjectScopedToken"]

	testDecodeProjectScopedToken(&testToken, t)
}

func TestTrustScopedToken(t *testing.T) {
	testToken := tokensToEncode["TrustScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeTrustScopedToken(tok, t)
}

func testDecodeTrustScopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["TrustScopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeTrustScopedToken(t *testing.T) {
	testToken := tokensToDecode["TrustScopedToken"]

	testDecodeTrustScopedToken(&testToken, t)
}

func TestFederatedUnscopedToken(t *testing.T) {
	testToken := tokensToEncode["FederatedUnscopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeFederatedUnscopedToken(tok, t)
}

func testDecodeFederatedUnscopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["FederatedUnscopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeFederatedUnscopedToken(t *testing.T) {
	testToken := tokensToDecode["FederatedUnscopedToken"]

	testDecodeFederatedUnscopedToken(&testToken, t)
}

func TestFederatedProjectScopedToken(t *testing.T) {
	testToken := tokensToEncode["FederatedProjectScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeFederatedProjectScopedToken(tok, t)
}

func testDecodeFederatedProjectScopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["FederatedProjectScopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeFederatedProjectScopedToken(t *testing.T) {
	testToken := tokensToDecode["FederatedProjectScopedToken"]

	testDecodeFederatedProjectScopedToken(&testToken, t)
}

func TestFederatedDomainScopedToken(t *testing.T) {
	testToken := tokensToEncode["FederatedDomainScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeFederatedDomainScopedToken(tok, t)
}

func testDecodeFederatedDomainScopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["FederatedDomainScopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeFederatedDomainScopedToken(t *testing.T) {
	testToken := tokensToDecode["FederatedDomainScopedToken"]

	testDecodeFederatedDomainScopedToken(&testToken, t)
}

func TestOAuthScopedToken(t *testing.T) {
	testToken := tokensToEncode["OAuthScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeOAuthScopedToken(tok, t)
}

func testDecodeOAuthScopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["OAuthScopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}

	am := decodedTok.GetAuthMethods()
	if am != 12 {
		t.Error("auth methods don't match")
	}

	if !reflect.DeepEqual(am.Decode(authMethods, sortedKeys), []string{"totp", "oauth1"}) {
		t.Error("auth methods don't match")
	}
}

func TestDecodeOAuthScopedToken(t *testing.T) {
	testToken := tokensToDecode["OAuthScopedToken"]

	testDecodeOAuthScopedToken(&testToken, t)
}

func TestSystemScopedToken(t *testing.T) {
	testToken := tokensToEncode["SystemScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeSystemScopedToken(tok, t)
}

func testDecodeSystemScopedToken(tok *string, t *testing.T) {
	testToken := tokensToEncode["SystemScopedToken"]

	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}
}

func TestDecodeSystemScopedToken(t *testing.T) {
	testToken := tokensToDecode["SystemScopedToken"]

	testDecodeSystemScopedToken(&testToken, t)
}

func TestApplicationCredentialScopedToken(t *testing.T) {
	testToken := tokensToEncode["ApplicationCredentialScopedToken"]

	tok, err := token.Encode(testToken, fernetKey)
	if err != nil {
		t.Error(err)
	}
	if debug {
		t.Logf("%s", *tok)
	}

	testDecodeApplicationCredentialScopedToken(tok, t)
}

func testDecodeApplicationCredentialScopedToken(tok *string, t *testing.T) {
	decodedTok, err := token.Decode(*tok, ttl, fernetKeys, false, debug)
	if err != nil {
		t.Error(err)
	}
	if debug {
		token.PrettyPrint(t.Logf, decodedTok, authMethods, sortedKeys)
	}

	testToken := tokensToEncode["ApplicationCredentialScopedToken"]
	if !reflect.DeepEqual(testToken, decodedTok) {
		t.Errorf(matchErr, testToken, decodedTok)
	}

	am := decodedTok.GetAuthMethods()
	if am != 16 {
		t.Error("auth methods don't match")
	}

	if !reflect.DeepEqual(am.Decode(authMethods, sortedKeys), []string{"application_credentials"}) {
		t.Error("auth methods don't match")
	}
}

func TestDecodeApplicationCredentialScopedToken(t *testing.T) {
	testToken := tokensToDecode["ApplicationCredentialScopedToken"]

	testDecodeApplicationCredentialScopedToken(&testToken, t)
}
