// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"io/ioutil"
	"testing"
)

func TestLMSKeyGeneration(t *testing.T) {
	// otstypecodes := []uint{LMOTSSHA256N32W1, LMOTSSHA256N32W2, LMOTSSHA256N32W4, LMOTSSHA256N32W8}
	// lmstypecodes := []uint{LMSSHA256M32H5, LMSSHA256M32H10, LMSSHA256M32H15, LMSSHA256M32H20, LMSSHA256M32H25}
	otstypecodes := []uint{LMOTSSHA256N32W1}
	lmstypecodes := []uint{LMSSHA256M32H5}
	for _, otstypecode := range otstypecodes {
		for _, lmstypecode := range lmstypecodes {
			lmspriv, priverr := GenerateLMSPrivateKey(lmstypecode, otstypecode)
			if priverr != nil {
				t.Errorf("failed to generate a private key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			}
			lmspub, _ := lmspriv.Public()

			ParseLMSPrivateKey(lmspriv.String())
			ParseLMSPublicKey(lmspub.String())

			lmspub, puberr := lmspriv.Public()
			if puberr != nil {
				t.Errorf("failed to generate the public key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			}

			parsedpriv, ppriverr := ParseLMSPrivateKey(lmspriv.String())
			if ppriverr != nil {
				t.Errorf("failed to parse a private key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			}

			parsedpub, ppuberr := ParseLMSPublicKey(lmspub.String())
			if ppuberr != nil {
				t.Errorf("failed to parse a public key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			}

			if lmspriv.String() != parsedpriv.String() {
				t.Errorf("parsed LMS private != LMS private key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			}

			if lmspub.String() != parsedpub.String() {
				t.Errorf("parsed LMS public != LMS public key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			}
		}
	}
}

func TestLMSSignandVerify(t *testing.T) {
	// otstypecodes := []uint{LMOTSSHA256N32W1, LMOTSSHA256N32W2, LMOTSSHA256N32W4, LMOTSSHA256N32W8}
	// lmstypecodes := []uint{LMSSHA256M32H5, LMSSHA256M32H10, LMSSHA256M32H15, LMSSHA256M32H20, LMSSHA256M32H25}
	otstypecodes := []uint{LMOTSSHA256N32W1}
	lmstypecodes := []uint{LMSSHA256M32H5}
	for _, otstypecode := range otstypecodes {
		for _, lmstypecode := range lmstypecodes {
			lmspriv, _ := GenerateLMSPrivateKey(lmstypecode, otstypecode)
			lmspub, _ := lmspriv.Public()
			files, _ := ioutil.ReadDir("testdata")
			for i := 0; i < 10; i++ {
				for _, fi := range files {
					message, _ := ioutil.ReadFile(fi.Name())
					lmssign, lmssignerr := lmspriv.Sign(message)
					if lmssignerr != nil {
						t.Errorf("lmssign error lmstypecode = %d, otstypecode = %d, file = %s", lmstypecode, otstypecode, fi.Name())
					}
					verifyerr := lmspub.Verify(message, lmssign)
					if verifyerr != nil {
						t.Errorf("verify error lmstypecode = %d, otstypecode = %d, file = %s", lmstypecode, otstypecode, fi.Name())
					}
				}
			}
		}
	}
}

// func BenchmarkKeyGeneration(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		lmspriv, _ := GenerateLMSPrivateKey(5, 1)
// 		lmspriv.Public()
// 	}
// }
