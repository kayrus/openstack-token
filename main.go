package main

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/vmihailenco/msgpack/v4"
)

var encoding = base64.RawURLEncoding

type Data struct {
	_msgpack struct{} `msgpack:",asArray"`
	Bytes    bool
	Data     string
}

type HexString string

/*
	Unsupported
	Version 4 - FederatedUnscoped
	Version none - FederatedScoped
	Version 5 - FederatedProjectScoped
	Version 6 - FederatedDomainScoped
	Version 7 - OauthScoped
*/

// Version 0
type Unscoped struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Version   int8
	UserID    Data
	Method    int8
	ExpiresAt float64
	AuditIDs  []HexString
}

// Version 1
type DomainScoped struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Version   int8
	UserID    Data
	Method    int8
	DomainID  HexString
	ExpiresAt float64
	AuditIDs  []HexString
}

// Version 2
type ProjectScoped struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Version   int8
	UserID    Data
	Method    int8
	ProjectID Data
	ExpiresAt float64
	AuditIDs  []HexString
}

// Version 3
type TrustScoped struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Version   int8
	UserID    Data
	Method    int8
	ProjectID Data
	ExpiresAt float64
	AuditIDs  []HexString
	TrustID   HexString
}

// Version 8
type SystemScoped struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Version   int8
	UserID    Data
	Method    int8
	System    HexString
	ExpiresAt float64
	AuditIDs  []HexString
}

// Version 9
type ApplicationCredentialScoped struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Version   int8
	UserID    Data
	Method    int8
	ProjectID Data
	ExpiresAt float64
	AuditIDs  []HexString
	AppCredID Data
}

func (a HexString) String() string {
	return encoding.EncodeToString([]byte(a))
}

func (d Data) String() string {
	if d.Bytes {
		return hex.EncodeToString([]byte(d.Data))
	}
	return d.Data
}

func main() {
	tok := os.Getenv("OS_AUTH_TOKEN")

	// align base64
	if v := len(tok) % 4; v > 0 {
		tok = tok + strings.Repeat("=", 4-v)
	}

	// base64 encoded 256bits size key
	key, err := fernet.DecodeKey(os.Getenv("OS_TOKEN_KEY"))
	if err != nil {
		log.Fatalln(err)
	}
	keys := []*fernet.Key{key}

	// verify tokens even if they were expired
	t := time.Hour*99999
	msg := fernet.VerifyAndDecrypt([]byte(tok), t, keys)
	if msg != nil {
		var v []interface{}
		err = msgpack.Unmarshal(msg, &v)
		if err != nil {
			log.Fatalln(err)
		}
		for _, v := range v {
			log.Printf("%+#v", v)
		}

		log.Printf("Version: %d", v[0])

		switch v[0].(int8) {
		case 0:
			t := Unscoped{}
			err = msgpack.Unmarshal(msg, &t)
			if err != nil {
				log.Fatalln(err)
			}
			log.Printf("UserID: %s", t.UserID)
			log.Printf("Method: %d", t.Method)
			log.Printf("ExpiresAt: %s", time.Unix(int64(t.ExpiresAt), 0))
			for i, v := range t.AuditIDs {
				log.Printf("AuditID%d: %s", i, v)
			}
		case 1:
			t := DomainScoped{}
			err = msgpack.Unmarshal(msg, &t)
			if err != nil {
				log.Fatalln(err)
			}
			log.Printf("UserID: %s", t.UserID)
			log.Printf("Method: %d", t.Method)
			log.Printf("DomainID: %s", t.DomainID)
			log.Printf("ExpiresAt: %s", time.Unix(int64(t.ExpiresAt), 0))
			for i, v := range t.AuditIDs {
				log.Printf("AuditID%d: %s", i, v)
			}
		case 2:
			t := ProjectScoped{}
			err = msgpack.Unmarshal(msg, &t)
			if err != nil {
				log.Fatalln(err)
			}
			log.Printf("UserID: %s", t.UserID)
			log.Printf("Method: %d", t.Method)
			log.Printf("Project: %s", t.ProjectID)
			log.Printf("ExpiresAt: %s", time.Unix(int64(t.ExpiresAt), 0))
			for i, v := range t.AuditIDs {
				log.Printf("AuditID%d: %s", i, v)
			}
		case 8:
			t := SystemScoped{}
			err = msgpack.Unmarshal(msg, &t)
			if err != nil {
				log.Fatalln(err)
			}
			log.Printf("UserID: %s", t.UserID)
			log.Printf("Method: %d", t.Method)
			log.Printf("System: %s", t.System)
			log.Printf("ExpiresAt: %s", time.Unix(int64(t.ExpiresAt), 0))
			for i, v := range t.AuditIDs {
				log.Printf("AuditID%d: %s", i, v)
			}
		case 9:
			t := ApplicationCredentialScoped{}
			err = msgpack.Unmarshal(msg, &t)
			if err != nil {
				log.Fatalln(err)
			}
			log.Printf("UserID: %s", t.UserID)
			log.Printf("Method: %d", t.Method)
			log.Printf("Project: %s", t.ProjectID)
			log.Printf("ExpiresAt: %s", time.Unix(int64(t.ExpiresAt), 0))
			for i, v := range t.AuditIDs {
				log.Printf("AuditID%d: %s", i, v)
			}
			log.Printf("AppCred: %s", t.AppCredID)
		}
	}

	// generate new project scope token to be valid for 24h
	timeNext := time.Now().Add(time.Hour * 24)
	auditID := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(auditID)

	projectID, err := hex.DecodeString(os.Getenv("OS_PROJECT_ID"))
	if err != nil {
		log.Fatal(err)
	}

	genToken := ProjectScoped{
		Version: 2,
		UserID: Data{
			Data: os.Getenv("OS_USER_ID"),
		},
		Method: 1,
		ProjectID: Data{
			Bytes: true,
			Data:  string(projectID),
		},
		ExpiresAt: float64(timeNext.Unix()),
		AuditIDs:  []HexString{HexString(auditID)},
	}

	b, err := msgpack.Marshal(&genToken)
	if err != nil {
		log.Fatal(err)
	}

	var newItem []interface{}
	err = msgpack.Unmarshal(b, &newItem)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range newItem {
		log.Printf("%+#v", v)
	}

	newToken, err := fernet.EncryptAndSign(b, keys[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Generated token: %s", strings.TrimRight(string(newToken), "="))
}
