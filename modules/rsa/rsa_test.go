package rsa

import (
	"fmt"
	"sync"
	"testing"
)

var grsa IRsa
var once sync.Once

func init() {
	once.Do(func() {
		grsa = NewRsa()
	})
}

var privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDtNOwhZfwINVb7ugcHgLIDEe8pbTJnuouU6Q1KMcPNAEKw37w+
4k0eyw9ZOk6fX6hdqFJ8XrovAEzQ1Kxebur3imtPscxCUacLOwEAvk7T4On83Pup
+D2KTKA6fjxA1ap/akvu3c3lrIhb3bYhYKytFz9aymO1T0jWrv/TLHbrOwIDAQAB
AoGAOgQQoNaNvwA0xxqnr3kVkNSpFwvDIUWp8ADUJEppplEi/pmqNAMrc5Wcqmkt
Y6OEzWtmyU5t4SMEpqrtgadFRk+EMgs+OpgHVbjdWjI3qaBd8LzgljlrqlkuQoaE
vL+MHFSmXv7CGC/+DXOfzo+Ov8WWjPyfytFA4wKX68dP+1ECQQD1A3UYQ93+e1X0
yWBDDsV/3UsiyYcYhSkE+wklsLxuGNO6qKPzQYves1gXfNtDEcs80VSuCllbCoTi
h5nRpd1jAkEA99fZliiViyaBacBvFwCOyTARhkz7YJu/Yj5Lw/piTURXPCfsA58R
2mGqKnhK7t5nD/m+1EJeqx3gy7xuMwEuSQJAWhtJZwEelUZ6mCmvEzpNe/bAeSyw
WF4wdbp05L2YrszGoTEACqgibmZ6kTjD0miq29UIVXFM52R49m50LVvYjQJBAMGz
PScSSO4cBgC0mR4NHYs3ujqQZ9a1YvpRXb2pLrLcuqEVQmwCIl3e/rN6mHXf9ASU
WARkasCp9UrF1gqe3aECQC9sNB6G05yfqnZxeEHuEYFsYxtCK36ymsEpVOb6TkaV
afpMY0oruW4fCr4XqzeKtbZiWOdnbJfJCYGyfZUDQoM=
-----END RSA PRIVATE KEY-----`)

var publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDtNOwhZfwINVb7ugcHgLIDEe8p
bTJnuouU6Q1KMcPNAEKw37w+4k0eyw9ZOk6fX6hdqFJ8XrovAEzQ1Kxebur3imtP
scxCUacLOwEAvk7T4On83Pup+D2KTKA6fjxA1ap/akvu3c3lrIhb3bYhYKytFz9a
ymO1T0jWrv/TLHbrOwIDAQAB
-----END PUBLIC KEY-----`)

func TestGenerateKey(t *testing.T) {
	priKey, pubKey, err := grsa.GenerateKey(1024)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(priKey), string(pubKey))
}

func TestSign(t *testing.T) {
	msg := []byte("RSA Digital Signature Testing")
	if _, err := grsa.Sign(msg, privateKey); err != nil {
		t.Error(err)
	}
}

func TestVerfiySign(t *testing.T) {
	msg := []byte("RSA Digital Signature Testing")
	signMsg, err := grsa.Sign(msg, privateKey)
	if err != nil {
		t.Error(err)
	}
	ret, err := grsa.VerifySign(msg, signMsg, publicKey)
	if err != nil || ret != true {
		t.Error(`Verify Sign failed`)
	}
}

func TestPrivateKeyEncrypt(t *testing.T) {
	prikey, err := grsa.GetPrivateKey(privateKey)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("RSA Encrypt Testing")
	if _, err := grsa.Encrypt(msg, prikey); err != nil {
		t.Error(err)
	}
}

func TestPublicKeyEncrypt(t *testing.T) {
	pubkey, err := grsa.GetPublicKey(publicKey)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("RSA Encrypt Testing")
	if _, err := grsa.Encrypt(msg, pubkey); err != nil {
		t.Error(err)
	}
}

func TestPrivateKeyEncryptPubicKeyDecrypt(t *testing.T) {
	prikey, err := grsa.GetPrivateKey(privateKey)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("RSA Encrypt Testing")
	emsg, err := grsa.Encrypt(msg, prikey)
	if err != nil {
		t.Error(err)
	}
	pubkey, err := grsa.GetPublicKey(publicKey)
	if err != nil {
		t.Error(err)
	}
	dmsg, err := grsa.Decrypt(emsg, pubkey)
	if err != nil {
		t.Error(err)
	}
	if string(dmsg) != string(msg) {
		t.Error(`decrypt error`)
	}
}

func TestPublicKeyEncryptPrivateKeyDecrypt(t *testing.T) {
	pubkey, err := grsa.GetPublicKey(publicKey)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("RSA Encrypt Testing")
	emsg, err := grsa.Encrypt(msg, pubkey)
	if err != nil {
		t.Error(err)
	}
	prikey, err := grsa.GetPrivateKey(privateKey)
	if err != nil {
		t.Error(err)
	}
	dmsg, err := grsa.Decrypt(emsg, prikey)
	if err != nil {
		t.Error(err)
	}
	if string(dmsg) != string(msg) {
		t.Error(`decrypt error`)
	}
}
