// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestHSSKeyGeneration(t *testing.T) {
	otstypecodes := []uint{1, 2, 3, 4}
	lmstypecodes := []uint{5}
	Ls := []int{1, 3, 5, 7}
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

				if len(hsspriv.String()) != len(phsspriv.String()) {
					t.Errorf("len(parsed HSS private) != len(HSS private key) when lmstypecode = %d, otstypecode = %d, L = %d", lmstypecode, otstypecode, L)
				}

				if !bytes.Equal([]byte(hsspub.String()), []byte(phsspub.String())) {
					t.Errorf("parsed HSS public != HSS public key when lmstypecode = %d, otstypecode = %d, L = %d", lmstypecode, otstypecode, L)
				}
			}
		}
	}
}

func TestHSSSignandVerify(t *testing.T) {
	otstypecodes := []uint{1, 2, 3, 4}
	lmstypecodes := []uint{5}
	Ls := []int{1, 3, 5, 7}
	for _, otstypecode := range otstypecodes {
		for _, lmstypecode := range lmstypecodes {
			for _, L := range Ls {
				hsspriv, _ := GenerateHSSPrivateKey(lmstypecode, otstypecode, L)
				files, _ := ioutil.ReadDir("testdata")
				for _, fi := range files {
					message, _ := ioutil.ReadFile(fi.Name())
					hsssign, hsssignerr := hsspriv.Sign(message)
					if hsssignerr != nil {
						t.Errorf("hsssign error lmstypecode = %d, otstypecode = %d, L = %d, file = %s", lmstypecode, otstypecode, L, fi.Name())
					}
					hsspub := hsspriv.Public()
					verifyerr := hsspub.Verify(message, hsssign)
					if verifyerr != nil {
						t.Errorf("verify error lmstypecode = %d, otstypecode = %d, L = %d, file = %s", lmstypecode, otstypecode, L, fi.Name())
					}
				}
			}
		}
	}
}
