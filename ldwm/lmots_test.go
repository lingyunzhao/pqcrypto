// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestOTSKeyGeneration(t *testing.T) {
	// ws := []uint{LMOTSSHA256N32W1, LMOTSSHA256N32W2, LMOTSSHA256N32W4, LMOTSSHA256N32W8}
	ws := []uint{LMOTSSHA256N32W1}
	for _, w := range ws {
		otspriv, priverr := GenerateOTSPrivateKey(w)
		if priverr != nil {
			t.Errorf("failed to generate a private key when w = %d", w)
		}

		otspub, puberr := otspriv.Public()
		if puberr != nil {
			t.Errorf("failed to generate the public key when w = %d", w)
		}

		parsedpriv, ppriverr := ParseOTSPrivateKey(otspriv.String())
		if ppriverr != nil {
			t.Errorf("failed to parse a private key when w = %d", w)
		}

		parsedpub, ppuberr := ParseOTSPublicKey(otspub.String())
		if ppuberr != nil {
			t.Errorf("failed to parse a public key when w = %d", w)
		}

		if otspriv.otstypecode != parsedpriv.otstypecode ||
			!bytes.Equal(otspriv.I, parsedpriv.I) ||
			!bytes.Equal(otspriv.x, parsedpriv.x) ||
			otspriv.q != parsedpriv.q {
			t.Errorf("parsed private key != private key w = %d", w)
		}

		if otspub.otstypecode != parsedpub.otstypecode ||
			!bytes.Equal(otspub.I, parsedpub.I) ||
			!bytes.Equal(otspub.K, parsedpub.K) ||
			otspub.q != parsedpub.q {
			t.Errorf("parsed public key != public key w = %d", w)
		}

	}
}

func TestOTSSignandVerify(t *testing.T) {
	// ws := []uint{LMOTSSHA256N32W1, LMOTSSHA256N32W2, LMOTSSHA256N32W4, LMOTSSHA256N32W8}
	ws := []uint{LMOTSSHA256N32W1}
	for _, w := range ws {
		otspriv, _ := GenerateOTSPrivateKey(w)
		otspub, _ := otspriv.Public()
		files, _ := ioutil.ReadDir("testdata")
		for _, fi := range files {
			message, _ := ioutil.ReadFile(fi.Name())
			otssign, otssignerr := otspriv.Sign(message)
			if otssignerr != nil {
				t.Errorf("otssign error w = %d, file = %s", w, fi.Name())
			}
			verifyerr := otspub.Verify(message, otssign)
			if verifyerr != nil {
				t.Errorf("verify error w = %d, file = %s", w, fi.Name())
			}
		}
	}
}
