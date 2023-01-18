// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"io/ioutil"
	"testing"
)

func TestLmsKeyGeneration(t *testing.T) {
	otsTypecodes := []uint{LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8}
	lmsTypecodes := []uint{LMS_SHA256_M32_H5, LMS_SHA256_M32_H10}
	for _, otsTypecode := range otsTypecodes {
		for _, lmsTypecode := range lmsTypecodes {
			lmsPriv, privErr := GenerateLmsPrivateKey(lmsTypecode, otsTypecode)
			if privErr != nil {
				t.Errorf("failed to generate a private key when lmstypecode = %d, otstypecode = %d", lmsTypecode, otsTypecode)
			}
			lmsPub, _ := lmsPriv.Public()

			ParseLmsPrivateKey(lmsPriv.String())
			ParseLmsPublicKey(lmsPub.String())

			lmsPub, pubErr := lmsPriv.Public()
			if pubErr != nil {
				t.Errorf("failed to generate the public key when lmstypecode = %d, otstypecode = %d", lmsTypecode, otsTypecode)
			}

			parsedPriv, pPrivErr := ParseLmsPrivateKey(lmsPriv.String())
			if pPrivErr != nil {
				t.Errorf("failed to parse a private key when lmstypecode = %d, otstypecode = %d", lmsTypecode, otsTypecode)
			}

			parsedPub, pPubErr := ParseLmsPublicKey(lmsPub.String())
			if pPubErr != nil {
				t.Errorf("failed to parse a public key when lmstypecode = %d, otstypecode = %d", lmsTypecode, otsTypecode)
			}

			if lmsPriv.String() != parsedPriv.String() {
				t.Errorf("parsed LMS private != LMS private key when lmstypecode = %d, otstypecode = %d", lmsTypecode, otsTypecode)
			}

			if lmsPub.String() != parsedPub.String() {
				t.Errorf("parsed LMS public != LMS public key when lmstypecode = %d, otstypecode = %d", lmsTypecode, otsTypecode)
			}
		}
	}
}

func TestLmsSignandVerify(t *testing.T) {
	otsTypecodes := []uint{LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8}
	lmsTypecodes := []uint{LMS_SHA256_M32_H5, LMS_SHA256_M32_H10}
	for _, otsTypecode := range otsTypecodes {
		for _, lmsTypecode := range lmsTypecodes {
			lmsPriv, _ := GenerateLmsPrivateKey(lmsTypecode, otsTypecode)
			lmsPub, _ := lmsPriv.Public()
			files, _ := ioutil.ReadDir("testdata")
			for i := 0; i < 10; i++ {
				for _, fi := range files {
					message, _ := ioutil.ReadFile(fi.Name())
					lmsSig, lmsSigErr := lmsPriv.Sign(message)
					if lmsSigErr != nil {
						t.Errorf("lmssign error lmstypecode = %d, otstypecode = %d, file = %s", lmsTypecode, otsTypecode, fi.Name())
					}
					verifyErr := lmsPub.Verify(message, lmsSig)
					if verifyErr != nil {
						t.Errorf("verify error lmstypecode = %d, otstypecode = %d, file = %s", lmsTypecode, otsTypecode, fi.Name())
					}
				}
			}
		}
	}
}
