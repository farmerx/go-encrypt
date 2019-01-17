package rsa

import (
	"bytes"
	"crypto/rand"
	crypto_rsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// IRsa ...
type IRsa interface {
	GenerateKey(bits int) (PrivateKey, PublicKey []byte, err error)
	Sign(message []byte, privateKey []byte) (cryptText []byte, err error)
	VerifySign(message []byte, sign []byte, PublicKey []byte) (bool, error)
	Encrypt(message []byte, key interface{}) ([]byte, error)
	Decrypt(message []byte, key interface{}) ([]byte, error)
	GetPublicKey(publickey []byte) (*crypto_rsa.PublicKey, error)
	GetPrivateKey(privatekey []byte) (*crypto_rsa.PrivateKey, error)
}

// Rsa ...
type Rsa struct {
}

// NewRsa ...
func NewRsa() IRsa {
	return new(Rsa)
}

// GenerateKey generates a new public/private key pair suitable for use with
// Encrypt and Decrypt.
func (grsa *Rsa) GenerateKey(bits int) (PrivateKey, PublicKey []byte, err error) {
	// Generate  private Key
	priKey, err := crypto_rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	derStream := x509.MarshalPKCS1PrivateKey(priKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	PrivateKey = pem.EncodeToMemory(block)
	// generate public key
	pubKey := &priKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	PublicKey = pem.EncodeToMemory(block)
	return
}

// Encrypt with privatekey or publickey
func (grsa *Rsa) Encrypt(message []byte, key interface{}) ([]byte, error) {
	output := bytes.NewBuffer(nil)
	switch keyVal := key.(type) {
	case *crypto_rsa.PrivateKey:
		if err := encryptByPrivateKey(keyVal, bytes.NewBuffer(message), output); err != nil {
			return nil, err
		}
	case *crypto_rsa.PublicKey:
		if err := encryptByPublicKey(keyVal, bytes.NewBuffer(message), output); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(`invild key`)
	}
	return ioutil.ReadAll(output)
}

// Decrypt with Privatekey or Publickey
func (grsa *Rsa) Decrypt(message []byte, key interface{}) ([]byte, error) {
	output := bytes.NewBuffer(nil)
	switch keyVal := key.(type) {
	case *crypto_rsa.PrivateKey:
		if err := decryptByPrivateKey(keyVal, bytes.NewBuffer(message), output); err != nil {
			return nil, err
		}
	case *crypto_rsa.PublicKey:
		if err := decryptByPublicKey(keyVal, bytes.NewBuffer(message), output); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(`invild key`)
	}
	return ioutil.ReadAll(output)
}

// GetPublicKey get public key
func (grsa *Rsa) GetPublicKey(publickey []byte) (*crypto_rsa.PublicKey, error) {
	// decode public key
	block, _ := pem.Decode(publickey)
	if block == nil {
		return nil, errors.New("get public key error")
	}
	// x509 parse public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if _, ok := pub.(*crypto_rsa.PublicKey); !ok {
		return nil, errors.New("get public key error")
	}

	return pub.(*crypto_rsa.PublicKey), err
}

// GetPrivateKey parse private key
func (grsa *Rsa) GetPrivateKey(privatekey []byte) (*crypto_rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatekey)
	if block == nil {
		return nil, errors.New("get private key error")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}
	pri2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if _, ok := pri2.(*crypto_rsa.PrivateKey); !ok {
		return nil, errors.New("get private key error")
	}
	return pri2.(*crypto_rsa.PrivateKey), nil
}
