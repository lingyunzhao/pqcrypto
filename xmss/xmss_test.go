// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"crypto/rand"
	"testing"
)

func TestXMSS(t *testing.T) {
	// xmsstys := []uint{XMSSSHA2H10W256, XMSSSHA2H16W256, XMSSSHA2H20W256, XMSSSHA2H10W512, XMSSSHA2H16W512, XMSSSHA2H20W512, XMSSSHAKE10W256, XMSSSHAKE16W256, XMSSSHAKE20W256, XMSSSHAKE10W512, XMSSSHAKE16W512, XMSSSHAKE20W512}
	xmsstys := []uint{XMSSSHA2H10W256} //, XMSSSHA2H16W256, XMSSSHA2H20W256, XMSSSHA2H10W512, XMSSSHA2H16W512, XMSSSHA2H20W512, XMSSSHAKE10W256, XMSSSHAKE16W256, XMSSSHAKE20W256, XMSSSHAKE10W512, XMSSSHAKE16W512, XMSSSHAKE20W512}
	for i := 0; i < len(xmsstys); i++ {
		xsk, xpk, _ := KeyGen(xmsstys[i])
		if xsk.Public().String() != xpk.String() {
			t.Errorf("xsk.Public() != xpk when XMSS types = %x", xmsstys[i])
		}
		for j := 0; j < 20; j++ {
			msg := make([]byte, 100)
			rand.Read(msg)
			xsig, _ := xsk.Sign(msg)
			if !xpk.Verify(msg, xsig) {
				t.Errorf("invalid signature when XMSS types = %x, j = %d", xmsstys[i], j)
			}
		}
		sxsk, serr := ParseSK(xsk.String())
		// _, serr := ParseSK(xsk.String())
		if serr != nil {
			t.Errorf("failed to parse private key when XMSS types = %x", xmsstys[i])
		}
		if sxsk.String() != xsk.String() {
			t.Errorf("parsed xsk != xsk when XMSS types = %x", xmsstys[i])
		}
		// fmt.Println(len(xsk.String()), len(sxsk.String()))
		sxpk, perr := ParsePK(xpk.String())
		if perr != nil {
			t.Errorf("failed to parse public key when XMSS types = %x", xmsstys[i])
		}
		if sxpk.String() != xpk.String() {
			t.Errorf("parsed xpk != xpk when XMSS types = %x", xmsstys[i])
		}
		for j := 0; j < 5; j++ {
			msg := make([]byte, 100)
			rand.Read(msg)
			xsig, _ := sxsk.Sign(msg)
			if !sxpk.Verify(msg, xsig) {
				t.Errorf("invalid signature using parsed key pair when XMSS types = %x, j = %d", xmsstys[i], j)
			}
		}
	}
}
