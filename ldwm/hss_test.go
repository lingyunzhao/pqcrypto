// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestHSSKeyGeneration(t *testing.T) {
	// otstypecodes := []uint{LMOTSSHA256N32W1, LMOTSSHA256N32W2, LMOTSSHA256N32W4, LMOTSSHA256N32W8}
	// lmstypecodes := []uint{LMSSHA256M32H5, LMSSHA256M32H10, LMSSHA256M32H15, LMSSHA256M32H20, LMSSHA256M32H25}
	otstypecodes := []uint{LMOTSSHA256N32W1}
	lmstypecodes := []uint{LMSSHA256M32H5}
	Ls := []int{3}
	for _, otstypecode := range otstypecodes {
		for _, lmstypecode := range lmstypecodes {
			for _, L := range Ls {

				hsspriv, priverr := GenerateHSSPrivateKey(lmstypecode, otstypecode, L)
				if priverr != nil {
					t.Errorf("failed to generate a private key when lmstypecode = %d, otstypecode = %d, L = %d", lmstypecode, otstypecode, L)
				}
				hsspub := hsspriv.Public()

				phsspriv, pprerr := ParseHSSPrivateKey(hsspriv.String())
				if pprerr != nil {
					t.Errorf("failed to parse a private key when lmstypecode = %d, otstypecode = %d, L = %d", lmstypecode, otstypecode, L)
				}

				phsspub, ppuerr := ParseHSSPublicKey(hsspub.String())
				if ppuerr != nil {
					t.Errorf("failed to parse a public key when lmstypecode = %d, otstypecode = %d, L = %d", lmstypecode, otstypecode, L)
				}

				if hsspriv.String() != phsspriv.String() {
					fmt.Println(hsspriv.String())
					fmt.Println(phsspriv.String())
					t.Errorf("parsed HSS private != HSS private key when lmstypecode = %d, otstypecode = %d, L = %d", lmstypecode, otstypecode, L)
				}

				if hsspub.String() != phsspub.String() {
					t.Errorf("parsed HSS public != HSS public key when lmstypecode = %d, otstypecode = %d, L = %d", lmstypecode, otstypecode, L)
				}
			}
		}
	}
}

func TestHSSSignandVerify(t *testing.T) {
	// otstypecodes := []uint{LMOTSSHA256N32W1, LMOTSSHA256N32W2, LMOTSSHA256N32W4, LMOTSSHA256N32W8}
	// lmstypecodes := []uint{LMSSHA256M32H5, LMSSHA256M32H10, LMSSHA256M32H15, LMSSHA256M32H20, LMSSHA256M32H25}
	otstypecodes := []uint{LMOTSSHA256N32W1}
	lmstypecodes := []uint{LMSSHA256M32H5}
	Ls := []int{3}
	for _, otstypecode := range otstypecodes {
		for _, lmstypecode := range lmstypecodes {
			for _, L := range Ls {
				hsspriv, _ := GenerateHSSPrivateKey(lmstypecode, otstypecode, L)
				hsspub := hsspriv.Public()
				files, _ := ioutil.ReadDir("testdata")
				for i := 0; i < 10; i++ {
					for _, fi := range files {
						message, _ := ioutil.ReadFile(fi.Name())
						hsssign, hsssignerr := hsspriv.Sign(message)
						if hsssignerr != nil {
							t.Errorf("hsssign error lmstypecode = %d, otstypecode = %d, L = %d, file = %s", lmstypecode, otstypecode, L, fi.Name())
						}
						verifyerr := hsspub.Verify(message, hsssign)
						if verifyerr != nil {
							t.Errorf("verify error lmstypecode = %d, otstypecode = %d, L = %d, file = %s", lmstypecode, otstypecode, L, fi.Name())
						}
					}
				}
			}
		}
	}
}
