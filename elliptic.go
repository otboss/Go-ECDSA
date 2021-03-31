package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/secp256k1"
)

//GeneratePrivateKey : ecdsa.PrivateKey
func GeneratePrivateKey() (*big.Int, error) {
	var privateKey *ecdsa.PrivateKey
	var privateKeyGenerationError error
	privateKey, privateKeyGenerationError = ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if privateKeyGenerationError != nil {
		return privateKey.D, privateKeyGenerationError
	}
	return privateKey.D, nil
}

//GeneratePublicKey :
func GeneratePublicKey(privateKey *big.Int) ecdsa.PublicKey {
	var pri ecdsa.PrivateKey
	pri.D, _ = new(big.Int).SetString(fmt.Sprintf("%x", privateKey), 16)
	pri.PublicKey.Curve = secp256k1.S256()
	pri.PublicKey.X, pri.PublicKey.Y = pri.PublicKey.Curve.ScalarBaseMult(pri.D.Bytes())

	publicKey := ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     pri.PublicKey.X,
		Y:     pri.PublicKey.Y,
	}

	return publicKey
}

//Signature :
type Signature struct {
	R *big.Int
	S *big.Int
}

//SignMessage : Generates a valid digital signature for javascript's elliptic library https://github.com/indutny/elliptic
func SignMessage(message string, privateKey *big.Int) (Signature, error) {
	var result Signature
	msgHash := fmt.Sprintf(
		"%x",
		sha256.Sum256([]byte(message)),
	)
	privateKeyStruct, privateKeyGenerationError := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if privateKeyGenerationError != nil {
		return result, privateKeyGenerationError
	}

	privateKeyStruct.D = privateKey
	hash, hashDecodeError := hex.DecodeString(msgHash)

	if hashDecodeError != nil {
		return result, hashDecodeError
	}

	signatureR, signatureS, signatureGenerationError := ecdsa.Sign(rand.Reader, privateKeyStruct, []byte(hash))
	if signatureGenerationError != nil {
		return result, signatureGenerationError
	}
	result.R = signatureR
	result.S = signatureS
	return result, nil
}

//VerifyMessage : Verifies signatures generated using the javascript elliptic library
// Set the double hash parameter to true if public key and signature generated from
// functions of this module, false otherwise
// https://github.com/indutny/elliptic
func VerifyMessage(message string, publicKey *ecdsa.PublicKey, signature Signature) (result bool, err error) {
	msgHash := fmt.Sprintf(
		"%x",
		sha256.Sum256([]byte(message)),
	)
	hash, hashDecodeError := hex.DecodeString(msgHash)
	if hashDecodeError != nil {
		return false, hashDecodeError
	}
	defer func() {
		if recover() != nil {
			result, err = ecdsa.Verify(publicKey, hash, signature.R, signature.S), nil
		}
	}()
	result, err = ecdsa.Verify(publicKey, []byte(hash), signature.R, signature.S), nil
	return

}
