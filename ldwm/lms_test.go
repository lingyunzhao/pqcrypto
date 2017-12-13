// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"io/ioutil"
	"testing"
)

func TestLMSKeyGeneration(t *testing.T) {
	// otstypecodes := []uint{1, 2, 3, 4}
	// lmstypecodes := []uint{5, 6, 7, 8, 9}
	otstypecodes := []uint{1, 2, 3, 4}
	lmstypecodes := []uint{5, 6}
	for _, otstypecode := range otstypecodes {
		for _, lmstypecode := range lmstypecodes {
			lmspriv, priverr := GenerateLMSPrivateKey(lmstypecode, otstypecode)
			if priverr != nil {
				t.Errorf("failed to generate a private key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			}
			lmspub, _ := lmspriv.Public()

			ParseLMSPrivateKey(lmspriv.String())
			ParseLMSPublicKey(lmspub.String())

			// lmspub, puberr := lmspriv.Public()
			// if puberr != nil {
			// 	t.Errorf("failed to generate the public key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			// }
			//
			// parsedpriv, ppriverr := ParseLMSPrivateKey(lmspriv.String())
			// if ppriverr != nil {
			// 	fmt.Printf(ppriverr.Error())
			// 	t.Errorf("failed to parse a private key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			// }
			//
			// parsedpub, ppuberr := ParseLMSPublicKey(lmspub.String())
			// if ppuberr != nil {
			// 	t.Errorf("failed to parse a public key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			// }
			//
			// if !bytes.Equal([]byte(lmspriv.String()), []byte(parsedpriv.String())) {
			// 	t.Errorf("parsed LMS private != LMS private key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			// }
			//
			// if !bytes.Equal([]byte(lmspub.String()), []byte(parsedpub.String())) {
			// 	t.Errorf("parsed LMS public != LMS public key when lmstypecode = %d, otstypecode = %d", lmstypecode, otstypecode)
			// }

			// fmt.Print(time.Now().Format(time.UnixDate), " | ")
			// fmt.Println(len(parsedpriv.String()), parsedpub.String())
		}
	}
}

func TestLMSSignandVerify(t *testing.T) {
	// otstypecodes := []uint{1, 2, 3, 4}
	// lmstypecodes := []uint{5, 6, 7, 8, 9}
	otstypecodes := []uint{1, 2, 3, 4}
	lmstypecodes := []uint{5, 6}
	for _, otstypecode := range otstypecodes {
		for _, lmstypecode := range lmstypecodes {
			lmspriv, _ := GenerateLMSPrivateKey(lmstypecode, otstypecode)
			// lmspub, _ := lmspriv.Public()
			// K0, _ := lmspriv.otspriv[0].Public()
			// K1, _ := lmspriv.otspriv[1].Public()
			// fmt.Printf("\nK = %x\nK = %x\n", K0.K, K1.K)
			files, _ := ioutil.ReadDir("testdata")
			for _, fi := range files {
				message, _ := ioutil.ReadFile(fi.Name())
				// otssign0, _ := lmspriv.otspriv[0].Sign(message)
				// otssign1, _ := lmspriv.otspriv[1].Sign(message)
				// fmt.Printf("\nK0: otssign = %x, otstype = %d, I = %x, q = %d\n", otssign0[len(otssign0)-10:], K0.otstypecode, K0.I[:10], K0.q)
				// fmt.Printf("\nK1: otssign = %x, otstype = %d, I = %x, q = %d\n", otssign1[len(otssign1)-10:], K1.otstypecode, K1.I[:10], K1.q)
				_, lmssignerr := lmspriv.Sign(message)
				// lmssign, lmssignerr := lmspriv.Sign(message)
				if lmssignerr != nil {
					t.Errorf("lmssign error lmstypecode = %d, otstypecode = %d, file = %s", lmstypecode, otstypecode, fi.Name())
				}
				// verifyerr := lmspub.Verify(message, lmssign)
				// if verifyerr != nil {
				// 	t.Errorf("verify error lmstypecode = %d, otstypecode = %d, file = %s", lmstypecode, otstypecode, fi.Name())
				// }
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
