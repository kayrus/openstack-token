package token

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"time"
	"unicode"

	"github.com/vmihailenco/msgpack/v4"
)

// https://github.com/openstack/keystone/blob/master/keystone/token/token_formatters.py

// to generate user friendly names
// run: stringer -type Version token/types.go
type Version int8

const (
	Unscoped Version = iota
	DomainScoped
	ProjectScoped
	TrustScoped
	FederatedUnscoped
	FederatedProjectScoped
	FederatedDomainScoped
	OAuthScoped
	SystemScoped
	ApplicationCredentialScoped
)

type Data struct {
	//lint:ignore U1000 this member is used by unmarshaller
	_msgpack struct{} `msgpack:",asArray"`
	Bytes    bool
	Value    string
}

func (d Data) String() string {
	if d.Bytes {
		return fmt.Sprintf("%s (bytes hex)", hex.EncodeToString([]byte(d.Value)))
	}
	return string(d.Value)
}

type Hex string

func (s Hex) String() string {
	str := string(s)

	if _, err := hex.DecodeString(str); err == nil {
		// already encoded hex
		return str
	}

	if v, err := base64.RawURLEncoding.DecodeString(str); err == nil {
		// base64 encoded string
		skip := false
		for _, c := range string(v) {
			if !unicode.IsSymbol(c) {
				skip = true
				break
			}
		}
		if !skip {
			return string(v)
		}
	}

	// simple string
	skip := false
	for _, c := range str {
		if unicode.IsSymbol(c) {
			skip = true
			break
		}
	}
	if !skip {
		return str
	}

	// raw data, encode it to string
	return fmt.Sprintf("%s (raw hex)", hex.EncodeToString([]byte(s)))
}

type AuthMethods int8

// Decode decodes auth methods depending on the amount of auth methods,
// configured in keystone.
func (m AuthMethods) Decode(authMethods map[int]string, sortedKeys []int) []string {
	var methods []string
	if m == 0 {
		return methods
	}

	v := float64(m)
	for _, k := range sortedKeys {
		i := float64(k)
		if math.Floor(v/i) == 1 {
			methods = append(methods, authMethods[k])
			v = v - i
		}
	}

	if len(methods) == 0 {
		return []string{fmt.Sprintf("%d", m)}
	}

	return methods
}

type Token interface {
	GetType() Version
	GetUserID() string
	GetAuthMethods() AuthMethods
	GetProjectID() string
	GetDomainID() string
	GetExpiresAt() time.Time
	GetAuditIDs() []string
	GetTrustID() string
	GetAccessTokenID() string
	GetSystemID() string
	GetAppCredID() string
	// Federated tokens
	GetFederatedGroupIDs() []string
	GetIdPID() string
	GetProtocolID() string
}

type UnscopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	ExpiresAt   float64
	AuditIDs    []Hex
}

func (t *UnscopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp UnscopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = UnscopedToken(s.tmp)

	return nil
}

func (t *UnscopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp UnscopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = Unscoped

	return msgpack.Marshal(s)
}

func (t *UnscopedToken) GetType() Version {
	return Unscoped
}

func (t *UnscopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *UnscopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *UnscopedToken) GetProjectID() string {
	return ""
}

func (t *UnscopedToken) GetDomainID() string {
	return ""
}

func (t *UnscopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *UnscopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *UnscopedToken) GetTrustID() string {
	return ""
}

func (t *UnscopedToken) GetAccessTokenID() string {
	return ""
}

func (t *UnscopedToken) GetSystemID() string {
	return ""
}

func (t *UnscopedToken) GetAppCredID() string {
	return ""
}

func (t *UnscopedToken) GetFederatedGroupIDs() []string {
	return nil
}

func (t *UnscopedToken) GetIdPID() string {
	return ""
}

func (t *UnscopedToken) GetProtocolID() string {
	return ""
}

type DomainScopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	DomainID    Hex
	ExpiresAt   float64
	AuditIDs    []Hex
}

func (t *DomainScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp DomainScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = DomainScopedToken(s.tmp)

	return nil
}

func (t *DomainScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp DomainScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = DomainScoped

	return msgpack.Marshal(s)
}

func (t *DomainScopedToken) GetType() Version {
	return DomainScoped
}

func (t *DomainScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *DomainScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *DomainScopedToken) GetProjectID() string {
	return ""
}

func (t *DomainScopedToken) GetDomainID() string {
	return t.DomainID.String()
}

func (t *DomainScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *DomainScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *DomainScopedToken) GetTrustID() string {
	return ""
}

func (t *DomainScopedToken) GetAccessTokenID() string {
	return ""
}

func (t *DomainScopedToken) GetSystemID() string {
	return ""
}

func (t *DomainScopedToken) GetAppCredID() string {
	return ""
}

func (t *DomainScopedToken) GetFederatedGroupIDs() []string {
	return nil
}

func (t *DomainScopedToken) GetIdPID() string {
	return ""
}

func (t *DomainScopedToken) GetProtocolID() string {
	return ""
}

type ProjectScopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	ProjectID   Data
	ExpiresAt   float64
	AuditIDs    []Hex
}

func (t *ProjectScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp ProjectScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = ProjectScopedToken(s.tmp)

	return nil
}

func (t *ProjectScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp ProjectScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = ProjectScoped

	return msgpack.Marshal(s)
}

func (t *ProjectScopedToken) GetType() Version {
	return ProjectScoped
}

func (t *ProjectScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *ProjectScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *ProjectScopedToken) GetProjectID() string {
	return t.ProjectID.String()
}

func (t *ProjectScopedToken) GetDomainID() string {
	return ""
}

func (t *ProjectScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *ProjectScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *ProjectScopedToken) GetTrustID() string {
	return ""
}

func (t *ProjectScopedToken) GetAccessTokenID() string {
	return ""
}

func (t *ProjectScopedToken) GetSystemID() string {
	return ""
}

func (t *ProjectScopedToken) GetAppCredID() string {
	return ""
}

func (t *ProjectScopedToken) GetFederatedGroupIDs() []string {
	return nil
}

func (t *ProjectScopedToken) GetIdPID() string {
	return ""
}

func (t *ProjectScopedToken) GetProtocolID() string {
	return ""
}

type TrustScopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	ProjectID   Data
	ExpiresAt   float64
	AuditIDs    []Hex
	TrustID     Hex
}

func (t *TrustScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp TrustScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = TrustScopedToken(s.tmp)

	return nil
}

func (t *TrustScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp TrustScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = TrustScoped

	return msgpack.Marshal(s)
}

func (t *TrustScopedToken) GetType() Version {
	return TrustScoped
}

func (t *TrustScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *TrustScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *TrustScopedToken) GetProjectID() string {
	return t.ProjectID.String()
}

func (t *TrustScopedToken) GetDomainID() string {
	return ""
}

func (t *TrustScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *TrustScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *TrustScopedToken) GetTrustID() string {
	return t.TrustID.String()
}

func (t *TrustScopedToken) GetAccessTokenID() string {
	return ""
}

func (t *TrustScopedToken) GetSystemID() string {
	return ""
}

func (t *TrustScopedToken) GetAppCredID() string {
	return ""
}

func (t *TrustScopedToken) GetFederatedGroupIDs() []string {
	return nil
}

func (t *TrustScopedToken) GetIdPID() string {
	return ""
}

func (t *TrustScopedToken) GetProtocolID() string {
	return ""
}

type FederatedUnscopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	GroupIDs    []Hex
	IdPID       Data
	ProtocolID  Hex
	ExpiresAt   float64
	AuditIDs    []Hex
}

func (t *FederatedUnscopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp FederatedUnscopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = FederatedUnscopedToken(s.tmp)

	return nil
}

func (t *FederatedUnscopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp FederatedUnscopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = FederatedUnscoped

	return msgpack.Marshal(s)
}

func (t *FederatedUnscopedToken) GetType() Version {
	return FederatedUnscoped
}

func (t *FederatedUnscopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *FederatedUnscopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *FederatedUnscopedToken) GetProjectID() string {
	return ""
}

func (t *FederatedUnscopedToken) GetDomainID() string {
	return ""
}

func (t *FederatedUnscopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *FederatedUnscopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *FederatedUnscopedToken) GetTrustID() string {
	return ""
}

func (t *FederatedUnscopedToken) GetAccessTokenID() string {
	return ""
}

func (t *FederatedUnscopedToken) GetSystemID() string {
	return ""
}

func (t *FederatedUnscopedToken) GetAppCredID() string {
	return ""
}

func (t *FederatedUnscopedToken) GetFederatedGroupIDs() []string {
	return getGroupIDs(t.GroupIDs)
}

func (t *FederatedUnscopedToken) GetIdPID() string {
	return t.IdPID.String()
}

func (t *FederatedUnscopedToken) GetProtocolID() string {
	return t.ProtocolID.String()
}

type FederatedProjectScopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	ProjectID   Data
	GroupIDs    []Hex
	IdPID       Data
	ProtocolID  Hex
	ExpiresAt   float64
	AuditIDs    []Hex
}

func (t *FederatedProjectScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp FederatedProjectScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = FederatedProjectScopedToken(s.tmp)

	return nil
}

func (t *FederatedProjectScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp FederatedProjectScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = FederatedProjectScoped

	return msgpack.Marshal(s)
}

func (t *FederatedProjectScopedToken) GetType() Version {
	return FederatedProjectScoped
}

func (t *FederatedProjectScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *FederatedProjectScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *FederatedProjectScopedToken) GetProjectID() string {
	return t.ProjectID.String()
}

func (t *FederatedProjectScopedToken) GetDomainID() string {
	return ""
}

func (t *FederatedProjectScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *FederatedProjectScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *FederatedProjectScopedToken) GetTrustID() string {
	return ""
}

func (t *FederatedProjectScopedToken) GetAccessTokenID() string {
	return ""
}

func (t *FederatedProjectScopedToken) GetSystemID() string {
	return ""
}

func (t *FederatedProjectScopedToken) GetAppCredID() string {
	return ""
}

func (t *FederatedProjectScopedToken) GetFederatedGroupIDs() []string {
	return getGroupIDs(t.GroupIDs)
}

func (t *FederatedProjectScopedToken) GetIdPID() string {
	return t.IdPID.String()
}

func (t *FederatedProjectScopedToken) GetProtocolID() string {
	return t.ProtocolID.String()
}

type FederatedDomainScopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	DomainID    Data
	GroupIDs    []Hex
	IdPID       Data
	ProtocolID  Hex
	ExpiresAt   float64
	AuditIDs    []Hex
}

func (t *FederatedDomainScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp FederatedDomainScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = FederatedDomainScopedToken(s.tmp)

	return nil
}

func (t *FederatedDomainScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp FederatedDomainScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = FederatedDomainScoped

	return msgpack.Marshal(s)
}

func (t *FederatedDomainScopedToken) GetType() Version {
	return FederatedDomainScoped
}

func (t *FederatedDomainScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *FederatedDomainScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *FederatedDomainScopedToken) GetProjectID() string {
	return ""
}

func (t *FederatedDomainScopedToken) GetDomainID() string {
	return t.DomainID.String()
}

func (t *FederatedDomainScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *FederatedDomainScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *FederatedDomainScopedToken) GetTrustID() string {
	return ""
}

func (t *FederatedDomainScopedToken) GetAccessTokenID() string {
	return ""
}

func (t *FederatedDomainScopedToken) GetSystemID() string {
	return ""
}

func (t *FederatedDomainScopedToken) GetAppCredID() string {
	return ""
}

func (t *FederatedDomainScopedToken) GetFederatedGroupIDs() []string {
	return getGroupIDs(t.GroupIDs)
}

func (t *FederatedDomainScopedToken) GetIdPID() string {
	return t.IdPID.String()
}

func (t *FederatedDomainScopedToken) GetProtocolID() string {
	return t.ProtocolID.String()
}

type OAuthScopedToken struct {
	UserID        Data
	AuthMethods   AuthMethods
	ProjectID     Data
	AccessTokenID Data
	ExpiresAt     float64
	AuditIDs      []Hex
}

func (t *OAuthScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp OAuthScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = OAuthScopedToken(s.tmp)

	return nil
}

func (t *OAuthScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp OAuthScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = OAuthScoped

	return msgpack.Marshal(s)
}

func (t *OAuthScopedToken) GetType() Version {
	return OAuthScoped
}

func (t *OAuthScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *OAuthScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *OAuthScopedToken) GetProjectID() string {
	return t.ProjectID.String()
}

func (t *OAuthScopedToken) GetDomainID() string {
	return ""
}

func (t *OAuthScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *OAuthScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *OAuthScopedToken) GetTrustID() string {
	return ""
}

func (t *OAuthScopedToken) GetAccessTokenID() string {
	return t.AccessTokenID.String()
}

func (t *OAuthScopedToken) GetSystemID() string {
	return ""
}

func (t *OAuthScopedToken) GetAppCredID() string {
	return ""
}

func (t *OAuthScopedToken) GetFederatedGroupIDs() []string {
	return nil
}

func (t *OAuthScopedToken) GetIdPID() string {
	return ""
}

func (t *OAuthScopedToken) GetProtocolID() string {
	return ""
}

type SystemScopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	SystemID    Hex
	ExpiresAt   float64
	AuditIDs    []Hex
}

func (t *SystemScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp SystemScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = SystemScopedToken(s.tmp)

	return nil
}

func (t *SystemScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp SystemScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = SystemScoped

	return msgpack.Marshal(s)
}

func (t *SystemScopedToken) GetType() Version {
	return SystemScoped
}

func (t *SystemScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *SystemScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *SystemScopedToken) GetProjectID() string {
	return ""
}

func (t *SystemScopedToken) GetDomainID() string {
	return ""
}

func (t *SystemScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *SystemScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *SystemScopedToken) GetTrustID() string {
	return ""
}

func (t *SystemScopedToken) GetAccessTokenID() string {
	return ""
}

func (t *SystemScopedToken) GetSystemID() string {
	return t.SystemID.String()
}

func (t *SystemScopedToken) GetAppCredID() string {
	return ""
}

func (t *SystemScopedToken) GetFederatedGroupIDs() []string {
	return nil
}

func (t *SystemScopedToken) GetIdPID() string {
	return ""
}

func (t *SystemScopedToken) GetProtocolID() string {
	return ""
}

type ApplicationCredentialScopedToken struct {
	UserID      Data
	AuthMethods AuthMethods
	ProjectID   Data
	ExpiresAt   float64
	AuditIDs    []Hex
	AppCredID   Data
}

func (t *ApplicationCredentialScopedToken) UnmarshalMsgpack(b []byte) error {
	type tmp ApplicationCredentialScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}

	err := msgpack.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = ApplicationCredentialScopedToken(s.tmp)

	return nil
}

func (t *ApplicationCredentialScopedToken) MarshalMsgpack() ([]byte, error) {
	type tmp ApplicationCredentialScopedToken
	var s struct {
		_msgpack struct{} `msgpack:",asArray"`
		Version  Version
		tmp
	}
	s.tmp = tmp(*t)
	s.Version = ApplicationCredentialScoped

	return msgpack.Marshal(s)
}

func (t *ApplicationCredentialScopedToken) GetType() Version {
	return ApplicationCredentialScoped
}

func (t *ApplicationCredentialScopedToken) GetUserID() string {
	return t.UserID.String()
}

func (t *ApplicationCredentialScopedToken) GetAuthMethods() AuthMethods {
	return t.AuthMethods
}

func (t *ApplicationCredentialScopedToken) GetProjectID() string {
	return t.ProjectID.String()
}

func (t *ApplicationCredentialScopedToken) GetDomainID() string {
	return ""
}

func (t *ApplicationCredentialScopedToken) GetExpiresAt() time.Time {
	return time.Unix(int64(t.ExpiresAt), 0).UTC()
}

func (t *ApplicationCredentialScopedToken) GetAuditIDs() []string {
	return getAuditIDs(t.AuditIDs)
}

func (t *ApplicationCredentialScopedToken) GetTrustID() string {
	return ""
}

func (t *ApplicationCredentialScopedToken) GetAccessTokenID() string {
	return ""
}

func (t *ApplicationCredentialScopedToken) GetSystemID() string {
	return ""
}

func (t *ApplicationCredentialScopedToken) GetAppCredID() string {
	return t.AppCredID.String()
}

func (t *ApplicationCredentialScopedToken) GetFederatedGroupIDs() []string {
	return nil
}

func (t *ApplicationCredentialScopedToken) GetIdPID() string {
	return ""
}

func (t *ApplicationCredentialScopedToken) GetProtocolID() string {
	return ""
}

func getAuditIDs(ids []Hex) []string {
	auditIDs := make([]string, len(ids))
	for i, v := range ids {
		auditIDs[i] = base64.RawURLEncoding.EncodeToString([]byte(v))
	}
	return auditIDs
}

func getGroupIDs(ids []Hex) []string {
	auditIDs := make([]string, len(ids))
	for i, v := range ids {
		auditIDs[i] = v.String()
	}
	return auditIDs
}
