package nacl

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// INacl ...
type INacl interface {
	GenerateKey() (privateKey, publicKey string, crc16 uint16, err error)
	Encrypt(msg []byte, publicKey string, nonce *[24]byte) ([]byte, error)
	Decrypt(msg []byte, privateKey string, nonce *[24]byte) ([]byte, error)
	GetNonce() (*[24]byte, error)
}

// Nacl ...
type Nacl struct {
}

// NewNacl ...
func NewNacl() INacl {
	return new(Nacl)
}

// GetNonce ...
func (nacl *Nacl) GetNonce() (*[24]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return &nonce, nil
}

// GenerateKey ...
func (nacl *Nacl) GenerateKey() (privateKey, publicKey string, crc16 uint16, err error) {
	senderPublicKey, senderPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return
	}
	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return
	}
	crc16 = checkCRC16Sum(bytesCombine(recipientPublicKey[:32], senderPrivateKey[:32]))
	publicKey = strings.ToUpper(hex.EncodeToString(recipientPublicKey[:32])) + strings.ToUpper(hex.EncodeToString(senderPrivateKey[:32]))
	privateKey = strings.ToUpper(hex.EncodeToString(senderPublicKey[:32])) + strings.ToUpper(hex.EncodeToString(recipientPrivateKey[:32]))
	return
}

// Encrypt ...
func (nacl *Nacl) Encrypt(msg []byte, publicKey string, nonce *[24]byte) ([]byte, error) {
	pubkey, err := hex.DecodeString(strings.ToLower(publicKey))
	if err != nil {
		return nil, err
	}
	var recipientPublicKey [32]byte
	var senderPrivateKey [32]byte
	copy(recipientPublicKey[:], pubkey[:32])
	copy(senderPrivateKey[:], pubkey[32:])
	encrypted := box.Seal(nonce[:], msg, nonce, &recipientPublicKey, &senderPrivateKey)
	return encrypted[24:], nil
}

// Decrypt ...
func (nacl *Nacl) Decrypt(msg []byte, privateKey string, nonce *[24]byte) ([]byte, error) {
	pubkey, err := hex.DecodeString(strings.ToLower(privateKey))
	if err != nil {
		return nil, err
	}
	var senderPublicKey [32]byte
	var recipientPrivateKey [32]byte
	copy(senderPublicKey[:], pubkey[:32])
	copy(recipientPrivateKey[:], pubkey[32:])
	decrypted, ok := box.Open(nil, msg, nonce, &senderPublicKey, &recipientPrivateKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}
