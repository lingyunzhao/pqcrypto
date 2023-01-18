// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestOtsKeyGeneration(t *testing.T) {
	ws := []uint{LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8}
	for _, w := range ws {
		otsPriv, privErr := GenerateOtsPrivateKey(w)
		if privErr != nil {
			t.Errorf("failed to generate a private key when w = %d", w)
		}

		otsPub, pubErr := otsPriv.Public()
		if pubErr != nil {
			t.Errorf("failed to generate the public key when w = %d", w)
		}

		parsedPriv, pPrivErr := ParseOtsPrivateKey(otsPriv.String())
		if pPrivErr != nil {
			t.Errorf("failed to parse a private key when w = %d", w)
		}

		parsedPub, pPubErr := ParseOtsPublicKey(otsPub.String())
		if pPubErr != nil {
			t.Errorf("failed to parse a public key when w = %d", w)
		}

		if otsPriv.otsTypecode != parsedPriv.otsTypecode ||
			!bytes.Equal(otsPriv.id, parsedPriv.id) ||
			!bytes.Equal(otsPriv.x, parsedPriv.x) ||
			otsPriv.q != parsedPriv.q {
			t.Errorf("parsed private key != private key w = %d", w)
		}

		if otsPub.otsTypecode != parsedPub.otsTypecode ||
			!bytes.Equal(otsPub.id, parsedPub.id) ||
			!bytes.Equal(otsPub.k, parsedPub.k) ||
			otsPub.q != parsedPub.q {
			t.Errorf("parsed public key != public key w = %d", w)
		}

	}
}

func TestOtsSignAndVerify(t *testing.T) {
	ws := []uint{LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8}
	for _, w := range ws {
		otsPriv, _ := GenerateOtsPrivateKey(w)
		otsPub, _ := otsPriv.Public()
		files, _ := ioutil.ReadDir("testdata")
		for _, fi := range files {
			message, _ := ioutil.ReadFile(fi.Name())
			otsSig, otsSigErr := otsPriv.Sign(message)
			if otsSigErr != nil {
				t.Errorf("otssign error w = %d, file = %s", w, fi.Name())
			}
			verifyErr := otsPub.Verify(message, otsSig)
			if verifyErr != nil {
				t.Errorf("verify error w = %d, file = %s", w, fi.Name())
			}
		}
	}
}
