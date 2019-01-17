package rsa

import (
	"crypto"
	"crypto/rand"
	crypto_rsa "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Sign appends a signed copy of message to out
// 实现的是利用RSA数字签名的函数，注意：用公钥加密，私钥解密就是加密通信，用私钥加密，公钥验证相当于数字签名
func (grsa *Rsa) Sign(message []byte, privateKey []byte) (cryptText []byte, err error) {
	// pem格式解码
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New(`pem decode private key error`)
	}
	// x509解码
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// 计算消息的hash值
	hash := sha256.New()
	if _, err := hash.Write(message); err != nil {
		return nil, err
	}
	//SignPKCS1v15使用RSA PKCS#1 v1.5规定的RSASSA-PKCS1-V1_5-SIGN签名方案计算签名。注意hashed必须是使用提供给本函数的hash参数对（要签名的）原始数据进行hash的结果。
	sign, err := crypto_rsa.SignPKCS1v15(rand.Reader, priKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return []byte{}, err
	}
	return sign, nil
}

// VerifySign verifies a signed message produced by Sign and return the message to out,
// 验证签名，验证签名用公钥验证，如果可以解密验证说明签名正确，否则错误
// 如果解密正确，那么就返回true,否着返回false
func (grsa *Rsa) VerifySign(message []byte, sign []byte, PublicKey []byte) (bool, error) {
	// pem格式解码
	block, _ := pem.Decode(PublicKey)
	if block == nil {
		return false, errors.New(`pem decode public key error`)
	}
	// x509解码
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	if _, ok := pubKey.(*crypto_rsa.PublicKey); !ok {
		return false, errors.New(`invalid public key`)
	}
	// 计算hash值
	hash := sha256.New()
	if _, err := hash.Write(message); err != nil {
		return false, err
	}
	// 校验签名
	if err := crypto_rsa.VerifyPKCS1v15(pubKey.(*crypto_rsa.PublicKey), crypto.SHA256, hash.Sum(nil), sign); err != nil {
		return false, err
	}
	return true, nil
}
