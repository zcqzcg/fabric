/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"github.com/hyperledger/fabric/bccsp/utils"
	"reflect"
	"strings"
	"testing"

	"github.com/hyperledger/fabric/bccsp/mocks"
	"github.com/stretchr/testify/assert"
)

func TestRSAPrivateKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := rsa.GenerateKey(rand.Reader, 512)
	assert.NoError(t, err)
	k := &rsaPrivateKey{lowLevelKey}

	assert.False(t, k.Symmetric())
	assert.True(t, k.Private())

	_, err = k.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not supported.")

	k.privKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.privKey = lowLevelKey
	ski = k.SKI()
	raw, _ := asn1.Marshal(rsaPublicKeyASN{N: k.privKey.N, E: k.privKey.E})
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	ecdsaPK, ok := pk.(*rsaPublicKey)
	assert.True(t, ok)
	assert.Equal(t, &lowLevelKey.PublicKey, ecdsaPK.pubKey)
}

func TestRSAPublicKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := rsa.GenerateKey(rand.Reader, 512)
	assert.NoError(t, err)
	k := &rsaPublicKey{&lowLevelKey.PublicKey}

	assert.False(t, k.Symmetric())
	assert.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.pubKey = &lowLevelKey.PublicKey
	ski = k.SKI()
	fmt.Println("SKI:", hex.EncodeToString(ski))
	raw, _ := asn1.Marshal(rsaPublicKeyASN{N: k.pubKey.N, E: k.pubKey.E})
	fmt.Println(hex.EncodeToString(raw))

	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	fmt.Println("ski2:::", hex.EncodeToString(ski2))
	assert.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, k, pk)

	bytes, err := k.Bytes()
	assert.NoError(t, err)
	bytes2, err := x509.MarshalPKIXPublicKey(k.pubKey)
	assert.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

}

func TestRSASignerSign(t *testing.T) {
	t.Parallel()

	signer := &rsaSigner{}
	verifierPrivateKey := &rsaPrivateKeyVerifier{}
	verifierPublicKey := &rsaPublicKeyKeyVerifier{}

	// Generate a key
	lowLevelKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)
	k := &rsaPrivateKey{lowLevelKey}
	pk, err := k.PublicKey()
	assert.NoError(t, err)

	// Sign
	msg := []byte("Hello World!!!")

	_, err = signer.Sign(k, msg, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	assert.Error(t, err)

	hf := sha256.New()
	hf.Write(msg)
	digest := hf.Sum(nil)
	sigma, err := signer.Sign(k, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	assert.NoError(t, err)

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	// Verify against msg, must fail
	err = rsa.VerifyPSS(&lowLevelKey.PublicKey, crypto.SHA256, msg, sigma, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "crypto/rsa: verification error")

	// Verify against digest, must succeed
	err = rsa.VerifyPSS(&lowLevelKey.PublicKey, crypto.SHA256, digest, sigma, opts)
	assert.NoError(t, err)

	valid, err := verifierPrivateKey.Verify(k, sigma, msg, opts)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "crypto/rsa: verification error"))

	valid, err = verifierPrivateKey.Verify(k, sigma, digest, opts)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, opts)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "crypto/rsa: verification error"))

	valid, err = verifierPublicKey.Verify(pk, sigma, digest, opts)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestDefinedRSASignerSign(t *testing.T) {
	t.Parallel()

	signer := &rsaSigner{}
	verifierPrivateKey := &rsaPrivateKeyVerifier{}
	verifierPublicKey := &rsaPublicKeyKeyVerifier{}

	// Generate a key
	lowLevelKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)
	k := &rsaPrivateKey{lowLevelKey}
	pk, err := k.PublicKey()
	assert.NoError(t, err)

	rsaPrvKeyPem := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCu+K74J+ecuGZD
xMlF9DkQmlZfW9gbQCdbGBzvNRndoHVPJmfCX4+L2c8Jr04io2uLdr0YQRBJJqng
r2QEAw5Is3zLpUq8r7U0Em9XFdpzIp3XEJYVRaAe8xIyqiC6SyqocOWtPETgetfY
07Fw/4UHTnY36nKPIIOAJG4Rlq9HkJPRMYkoCD4OuoOO/XMI+ZRNR9fijx0gyCVz
poPnYcSVtYbnsM0j74DIzzwn/4hOq3jO2s4/gXaArYWegSy5+/DkWW2/nAzHlBfO
1zvQbQUrfraHuTCaqYJLom4fC+Loqm12JzvcgyaaWaAUgWTgW/b/YhQejpD5XD46
s27S9uGFAgMBAAECggEBAImN0/AfXwRkK3FniVxHbX1R+EkraS+zNb11rXmY42bK
uK6q4LN8cNtfNlbEzMaKdwfDJ1GkBOudS7vp5tUImfgpsxheL+06rVfsjj+GXKBb
PH9Q+MxsWj86lLnj6arLYRPe/ZE9amCX8ozxj/PnzWs7EdFPrRQ8WWUqPqXxMoct
I2KZRWLnPh34G5z/WRh+ZfJPXhylNGVEdr8xznnCztaoLodMhOUFp5SuY25NZEM/
mVtXfZ+JCbfYeqU99zZUFXlBikdPZgjzpwET/E6j1PPgm2KOEcelFGFTGPDD4UGX
ycwY9P/z5/SeYbDSdNEATWWov0e71JeaWQBlSiQyNRkCgYEA01qN7tTCrJ2KEiei
zuP1GjKvf7Y5tP86a69XjsHdtQ/FZZzGrmKSm0IK6GlQ1YchLDhGNMsny21lnxP1
78xxD4q5wtAOQy4uvfQPvNAQrWSsNYPH8W2xl3+IjvNS2xj6R3dTE7ngM6B30hyi
CqRVDj5Qiq92YzA+Eq/ehEZrT/8CgYEA0+6rwGy/le2JPJSVtZDaEksQTs/eWa35
571KMHIeIPJAcGXR8PSlyQEO1oTaHMyrLeqZC/B58GUa82bV3ctzTzt6bJ0LXGyP
N8kEG6SllZRU/znQ99XzjfL9Ne+RJrWoFQros7uZmTArQEiGRkXR3uqOjk+WSL0r
FflnpAj4jnsCgYBUvFJ5NV3TXNn1S2TPs78ZwMZx2noqYcVnVQYymvErXWZTxdY2
JhkHHCRJZ6fb4/BdzTYAho6u1W5Pp+4LNRkDFShCva1qK8Lbr1T76yM0kU8lqW7p
EYSI672xKkbGxq3ZJzLsjrIfoK9JUud4gsgDDOK3p388ZyQL0+zPdXgiuwKBgALd
eSjyz2xBd9d/0r5PpQMWTLQkD0d7GKPPZU9eW5XqcICUf9AYHp2nDAJObXxyL+ZB
A6yrpZpgY4ri2wVSmM57aV5KiTrIpO8GIq4U/cAV70g8Cd0v4UkL/exavsWdMxaF
vTugz6TIh+0ojdgpXXr8BM1buhZlqE11v7byABo9AoGBAKHoIaZBtf9Q+kzJWDfO
nnFsox4lHSKBZCtUwAZgdb85c9cHxK/eL6jRlJ6JxT3omVdQpfeWuBmEBTs5rH6R
81sTeL1DrNtH3Dtbjxd0X/CJhQu2FIShO72ejGLXLnjae4I8Vufvg0z2A7Z6FckP
17g6j90ynG3CyobFCR9fUzpU
-----END PRIVATE KEY-----
`

	// import key
	rsaPrvKey, err := utils.PEMtoPrivateKey([]byte(rsaPrvKeyPem), nil)
	if err != nil {
		fmt.Println("keyimport::", err)
	}

	rsaPrvKey1 := &rsaPrivateKey{rsaPrvKey.(*rsa.PrivateKey)}
	hf := sha256.New()
	a, _ := hex.DecodeString("4e6231f8d45faf0caae3196379868c5bba7a7ec402fc3af084ffd93b4972da8a")
	//digest123 := []byte(`iʩ��?ͷh��W��aH(��*ٴo�i�%K���`)
	hf.Write(a)
	digest123 := hf.Sum(nil)
	//digest123 :=
	//hf.Write(digest123)
	//digest123 = hf.Sum(nil)
	sigg, err := signer.Sign(rsaPrvKey1, digest123, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("digest123 sign::", hex.EncodeToString(sigg))
	fmt.Println(reflect.TypeOf(sigg))
	rsaPublicKey, err := rsaPrvKey1.PublicKey()
	if err != nil {
		fmt.Println(err)
	}
	b, err := verifierPublicKey.Verify(rsaPublicKey, sigg, digest123, nil)
	fmt.Println(b, err)
	nodeSignature := `7171e105001f127045dacd16b537c83b3ff0ed5b1134695fd2aa3dd07f73c596bdd1284622d5a0b27fe0cbc61ba58330c7c58aebfef40d9f81ccdd22365a36894c49bb300a6f7128efe5fddfaa3ae58ac3599d03fbe045be1f803641fa020af06a05a83ac6ae2ca9954f0e25dbc5fd2b5e141417fa469e01ab8ddf059eb9a0b3898658c4035c89094399569a2d6fad2657fba4ad98d55910bac0d1f589c0c15e0e0782ea6649f5eab4d0af6faf8f2e163f9983301f2ef012561eb2953f4225680413612203de347ecdcc881da1b01b898e9bb5c4e36ff9ce621442490fb025ab7297086af855b4eaa10b87ee8e10e70acc8ce2734d544eda912620c34860ff3b`
	nodeSigBytes, _ := hex.DecodeString(nodeSignature)
	b, err = verifierPublicKey.Verify(rsaPublicKey, nodeSigBytes, digest123, nil)
	fmt.Println(b, err)

	// Sign
	msg := []byte("Hello World!!!")

	_, err = signer.Sign(k, msg, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	assert.Error(t, err)

	hf.Write(msg)
	digest := hf.Sum(nil)
	sigma, err := signer.Sign(k, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	assert.NoError(t, err)

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	// Verify against msg, must fail
	err = rsa.VerifyPSS(&lowLevelKey.PublicKey, crypto.SHA256, msg, sigma, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "crypto/rsa: verification error")

	// Verify against digest, must succeed
	err = rsa.VerifyPSS(&lowLevelKey.PublicKey, crypto.SHA256, digest, sigma, opts)
	assert.NoError(t, err)

	valid, err := verifierPrivateKey.Verify(k, sigma, msg, opts)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "crypto/rsa: verification error"))

	valid, err = verifierPrivateKey.Verify(k, sigma, digest, opts)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, opts)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "crypto/rsa: verification error"))

	valid, err = verifierPublicKey.Verify(pk, sigma, digest, opts)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestRSAVerifiersInvalidInputs(t *testing.T) {
	t.Parallel()

	verifierPrivate := &rsaPrivateKeyVerifier{}
	_, err := verifierPrivate.Verify(nil, nil, nil, nil)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "Invalid options. It must not be nil."))

	_, err = verifierPrivate.Verify(nil, nil, nil, &mocks.SignerOpts{})
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "Opts type not recognized ["))

	verifierPublic := &rsaPublicKeyKeyVerifier{}
	_, err = verifierPublic.Verify(nil, nil, nil, nil)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "Invalid options. It must not be nil."))

	_, err = verifierPublic.Verify(nil, nil, nil, &mocks.SignerOpts{})
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "Opts type not recognized ["))
}
