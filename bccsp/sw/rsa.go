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
	"encoding/hex"
	"fmt"
	"github.com/hyperledger/fabric/common/flogging"

	"github.com/hyperledger/fabric/bccsp"
)

var logging = flogging.MustGetLogger("bccsp-sw-rsa.go")

type rsaSigner struct{}

func (s *rsaSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	if opts == nil {
		opts = crypto.SHA256
	}

	return k.(*rsaPrivateKey).privKey.Sign(rand.Reader, digest, opts)
}

type rsaPrivateKeyVerifier struct{}

func (v *rsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	//logging.Info("Entering verify rsaPrivateKey, signature is:",signature)
	if opts != nil {
		//return false, errors.New("Invalid options. It must not be nil.")
		switch opts.(type) {
		case *rsa.PSSOptions:
			err := rsa.VerifyPSS(&(k.(*rsaPrivateKey).privKey.PublicKey),
				(opts.(*rsa.PSSOptions)).Hash,
				digest, signature, opts.(*rsa.PSSOptions))
			if err == nil {
				//logging.Info("SUCCESS verify rsaPublicKeyKeyVerifier, signature is:",hex.EncodeToString(signature))
			} else {
				logging.Info("FAILURE verify rsaPublicKeyKeyVerifier, signature is:", hex.EncodeToString(signature))
			}
			return err == nil, err
		default:
			return false, fmt.Errorf("Opts type not recognized [%s] with RSAPrivateKey", opts)
		}
	}
	err := rsa.VerifyPKCS1v15(&k.(*rsaPrivateKey).privKey.PublicKey, crypto.SHA256, digest, signature)
	if err == nil {
		//logging.Info("SUCCESS verify rsaPublicKeyKeyVerifier, signature is:",hex.EncodeToString(signature))
	} else {
		logging.Info("FAILURE verify rsaPublicKeyKeyVerifier, signature is:", hex.EncodeToString(signature))
	}
	return err == nil, err
}

type rsaPublicKeyKeyVerifier struct{}

func (v *rsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	//logging.Info("Entering verify rsaPublicKeyKeyVerifier, signature is:",signature)
	if opts != nil {
		//return false, errors.New("Invalid options. It must not be nil.")
		switch opts.(type) {
		case *rsa.PSSOptions:
			err := rsa.VerifyPSS(k.(*rsaPublicKey).pubKey,
				(opts.(*rsa.PSSOptions)).Hash,
				digest, signature, opts.(*rsa.PSSOptions))
			if err == nil {
				//logging.Info("SUCCESS verify rsaPublicKeyKeyVerifier, signature is:",hex.EncodeToString(signature))
			} else {
				logging.Info("FAILURE verify PSSOptions rsaPublicKeyKeyVerifier, signature is:", hex.EncodeToString(signature))
			}

			return err == nil, err
		default:
			return false, fmt.Errorf("Opts type not recognized [%s] with RSAPublicKey", opts)
		}
	}
	err := rsa.VerifyPKCS1v15((k.(*rsaPublicKey)).pubKey, crypto.SHA256, digest, signature)
	if err == nil {
		//logging.Info("SUCCESS verify rsaPublicKeyKeyVerifier, signature is:",hex.EncodeToString(signature))
	} else {
		logging.Info("FAILURE verify  VerifyPKCS1v15  rsaPublicKeyKeyVerifier, signature is:", hex.EncodeToString(signature))
	}
	return err == nil, err
}
