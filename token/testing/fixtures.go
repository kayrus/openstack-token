package testing

import (
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/kayrus/openstack-token/token"
)

var (
	am = []string{
		"password",
		"token",
		"oauth1",
		"totp",
		"application_credentials",
	}
	authMethods, sortedKeys = token.GenerateAuthMethodsMapList(am)
	oneSecond               = time.Second
	ttl                     = time.Hour * 999999
	fernetKey, _            = fernet.DecodeKey("tjQoua64RZEccGn_MNbCBhLfMYpaVrLOL2pCaJHjrP0=")
	fernetKeys              = []*fernet.Key{fernetKey}
	auditID1, _             = base64.RawURLEncoding.DecodeString("XLKFCG23T66BbaJ-uC7uWg")
	auditID2, _             = base64.RawURLEncoding.DecodeString("sGEDVFDgTDO4rumtnbui5g")
	expiresAt               = float64(time.Date(3000, 3, 12, 12, 12, 12, 123456000, time.UTC).Unix())
	auditIDs                = []token.Hex{
		token.Hex(auditID1),
		token.Hex(auditID2),
	}
	uID, _ = hex.DecodeString("28f6d90bb6d948ac9105b90bcc1e3a84")
	userID = token.Data{
		Bytes: true,
		Value: string(uID),
	}
	domainID1 = token.Hex("default")
	domainID2 = token.Data{
		Value: "61f3033e9e6e4d38bcee2bb7d2fa6b49",
	}
	pID, _    = hex.DecodeString("5b7d00a6d7a94f8fb57de9c6ef858ea8")
	projectID = token.Data{
		Bytes: true,
		Value: string(pID),
	}
	trustID  = token.Hex("037fdfd5a2fd4198842bfaef79c52dec")
	groupID1 = "dc46b510355443e1a28405f390243e50"
	groupID2 = "1e599a41898547cc874e211b758e074d"
	groupIDs = []token.Hex{
		token.Hex(groupID1),
		token.Hex(groupID2),
	}
	idPID = token.Data{
		Value: "4138615faa26455ea84cf116666e7df2",
	}
	protocolID     = token.Hex("1234")
	groupIDRaw1, _ = hex.DecodeString(groupID1)
	groupIDRaw2, _ = hex.DecodeString(groupID2)
	groupIDsRaw    = []token.Hex{
		token.Hex(groupIDRaw1),
		token.Hex(groupIDRaw2),
	}
	atID, _       = hex.DecodeString("28f6d90bb6d948ac9105b90bcc1e3a84")
	accessTokenID = token.Data{
		Bytes: true,
		Value: string(atID),
	}
	systemID  = token.Hex("all")
	appCredID = token.Data{
		Value: "e87cdff53bec42b3990eaa0b7684feaa",
	}

	tokensToEncode = map[string]token.Token{
		"UnscopedToken": &token.UnscopedToken{
			UserID:      userID,
			AuthMethods: 1,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
		},
		"DomainScopedToken": &token.DomainScopedToken{
			UserID:      userID,
			AuthMethods: 1,
			DomainID:    domainID1,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
		},
		"ProjectScopedToken": &token.ProjectScopedToken{
			UserID:      userID,
			AuthMethods: 1,
			ProjectID:   projectID,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
		},
		"TrustScopedToken": &token.TrustScopedToken{
			UserID:      userID,
			AuthMethods: 1,
			ProjectID:   projectID,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
			TrustID:     trustID,
		},
		"FederatedUnscopedToken": &token.FederatedUnscopedToken{
			UserID:      userID,
			AuthMethods: 1,
			GroupIDs:    groupIDs,
			IdPID:       idPID,
			ProtocolID:  protocolID,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
		},
		"FederatedProjectScopedToken": &token.FederatedProjectScopedToken{
			UserID:      userID,
			AuthMethods: 1,
			ProjectID:   projectID,
			GroupIDs:    groupIDsRaw,
			IdPID:       idPID,
			ProtocolID:  protocolID,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
		},
		"FederatedDomainScopedToken": &token.FederatedDomainScopedToken{
			UserID:      userID,
			AuthMethods: 1,
			DomainID:    domainID2,
			GroupIDs:    groupIDsRaw,
			IdPID:       idPID,
			ProtocolID:  protocolID,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
		},
		"OAuthScopedToken": &token.OAuthScopedToken{
			UserID:        userID,
			AuthMethods:   12,
			ProjectID:     projectID,
			AccessTokenID: accessTokenID,
			ExpiresAt:     expiresAt,
			AuditIDs:      auditIDs,
		},
		"SystemScopedToken": &token.SystemScopedToken{
			UserID:      userID,
			AuthMethods: 1,
			SystemID:    systemID,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
		},
		"ApplicationCredentialScopedToken": &token.ApplicationCredentialScopedToken{
			UserID:      userID,
			AuthMethods: 16,
			ProjectID:   projectID,
			ExpiresAt:   expiresAt,
			AuditIDs:    auditIDs,
			AppCredID:   appCredID,
		},
	}

	tokensToDecode = map[string]string{
		"ExpiredToken":                     "gAAAAABgHr_jrMohx1tHUzeoPfO0Ou4SMtCMMOZTwEhXQS77kVbkSWCfRXhX4kWOeXnLNZerc6XhN4G_4xEpF8LtM-7hEXP17qSOIaWz-TZZgPHveyAgmWR8G0lzeBNwpQGEx1d-d7OQxP830IVBGgUgowiGLieiHvNqcg7HBkHJZ-WTwZPxnxQ",
		"UnscopedToken":                    "gAAAAABgHrIyBhOzoRyZGuHEMGAAVVujiUDFQAzUbzJsVPpG75ijl809KHHaHBwaz1iliErkyFcTLPMSmrCnE4uRCCh1FfXlJ576zSVxBL0I36vzL-ETrmhG6UrrNlhHTj_9Zf9o6Q_OgqpLW8axNtZvt1JYx5DXNwrKXmaRo5T3WmOM1VjZNAw",
		"DomainScopedToken":                "gAAAAABgHrIytdipNY-tRoPjRYf4lTKuIJxAscsPcqaDlYVjstlGVCOmJ8VbIfKNj1DEn07Ff2GV44RTmbMGExh9PxdSbwhnrWOGRZKxnKH9KdicnW1FKlqm-5XN_VAJ05o3rWMtd061qdKtgyIgYS6BheTWFSedQrtH2Yc1a-B9oyq28R2GWXc",
		"ProjectScopedToken":               "gAAAAABgHrIyjxg1uhHRszMPJ5c_dbs06ijQsiRc2aKbquUZeSsQgm7NtYZ8J3kqyofilwPx0Y5wDq4GS7inZeDP6Xj1mcYl_dd9GkXYoRfAk9Adv6qUfPQzajoVJgqnwcIF8jntnd2G2eSJU8uCqf60mF79pT9j5jKF4l-GmOHK5GxzvicdkEVTdNLOkPLS_BnCyXJ2gvdR",
		"TrustScopedToken":                 "gAAAAABgHrIyNAsJA5S6WHMGOkUeQKfBTBfX4_uceb15e7OGvUuPXRFjjTNRAi3BVkadWTfNweqqpiRJ5-G7P2Xamzd5D99KNIiRlnSUkgdu2WXtSc5BbZZYNLPJ3B9mHtoKpBZv1jAXanoHcTZ38_IYxaqFjkMhyncMPVHPb-fXodysbxJENf8mqy8_PERjzV_qBVMNrua0I3YEqGoWHckUi4YxiWH7ji4LFPevQPoG_gKWTpqB3qo",
		"FederatedUnscopedToken":           "gAAAAABgHrIyheA9WDwsJMFlaBBvLdXdmBFNo4J2T27k25CUyEX5e7C9AQfqMr5KZAxJUoTmGAG_umD85ssQdcowVaKMj5OSw0HAGCO_H9u2DHs6X3plMvcBpSdnN8RiHiaZRMRc-RT_sZhlhiMtyUsXaTfP9rPHjux2oYHHfqJhtk-LSGsq5Aw4rb3jSG1Ju3rJ3aRK2pnlKnp3Dj9DaAmX81H0cKdgyoA40vbk2UQWWfbenUhFttp2xw9Kdzioi54F7TJJkM3uOWvqPCBN2KxjhEBsAVVDgzrhZ6sT-RNvLWgOdmKjRCM6Z-aBF3inVsuIxDZAajJs",
		"FederatedProjectScopedToken":      "gAAAAABgHrIyMLJsW3mY5DiXm19L3haVHffOqx5EA8j0pqE4_sig84P9-aif8M86n8AcLPOsFnoqG0-ebqrbxxbsWnIEa-w9wPzUYqsaMxnBx9ljOMgkV4rMCKi4cbod7ogTEqUnYt46mqTdo6ZlVlMHI8AHJ4sTvi37AZ8cm-5wAGbyhC8ImBy2T2HICudX2FtnisyKk62t2QtiIRd7yCpBMOmhQG-u6kStKzaExGSADYNJDdYXrgB3cV0tIkspipmJ5J4y7TVNABrQyAyX4HJXuAQFst_xseMKQIbG_DryErdx3jrQLRI",
		"FederatedDomainScopedToken":       "gAAAAABgHrIyHxjgQQvUEjNE1AlVAZEYzPug_KQgs1BD0uO5jN8BkyOQymHPIuA-9AWSzHxDCN15x_MOrGWX6XpKq1dtJvUcb_VMFtOuLQ55oXeKaYt9XGsPm-BOQSmIMWK4z8PSIe2PF0lyc242DeD6ZcJv4TLvpbXH5l1IBNESeOKCERLhSsoQyj6xxnfOdjiRdvn5znXx1X65bGq5fJBZbbyuVhx0Yi4ansAbPPLEAkq7CJX2d5iEQcznDlzBQU8MSz9hGZ9E8uq2wPDxM0UCIFGFIlYtA5_aoxrIWO1fCzepVtESUsR6fOKnFZYXPTGFKmiXtV-O",
		"OAuthScopedToken":                 "gAAAAABgHrIylItBPFIBMMeudyFq7QCQkAUFNXzhT6vuOqkoHoDhAH32NG509P_qCFheqOI90NMtA8AJCCszE58zeeTi0JJDymzR6tztcok5s-tZiVIptVHt7i-y5ZAH8_HvreryGNbNtb2Dz9CRm3hCVxl8-Z-dOPCeKQNYXBYoDv9RSU4q6av_y3FFimvTpvmA4Xs8PwiST_JMxi8OutUOpNL2BxwsOA",
		"SystemScopedToken":                "gAAAAABgHrIy_I3JrLV7J_O8aUoLWkt3eG-DUVl4iP2P-poSCZgbeDfdlUDVQtzeTb9jKJlGy_jB1S-vBhPGrC43VqzeNjDgrCo9tUrNVQ_lGrjQ4BHA--SRg5t3W0iMUDZWhrn95oGP0b2ZFvAUyiCMURcmWzfpugxk0sL-3sfX4nEPMRT6VpA",
		"ApplicationCredentialScopedToken": "gAAAAABgHrIyY1PVnLuy5MSrJ5K6uVVG1qH6lqaDGiUCoDGsEDyAzQ22rak-9J7WZFjQL7nNzkHZIdgOfouWCwUs82wPdyIYi1FXN7hsLAQtgVHxzfgorP7qIa9xQraJNA1W8LnV_hpFh_s301Z84f0spU-lJpmX-IAxkiVal2472r6biWbbcKgbFqiCtNrnyZDV-qC1ZTos0SvtntoRfjbp-7UJVRTZ3X2L9VqINCcc92DJR_2UvTM",
	}
)
