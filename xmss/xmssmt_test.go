// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"crypto/rand"
	"testing"
)

func TestXMSSMT(t *testing.T) {
	xmssmttys := []uint{XMSSMTSHA2H20D2W256, XMSSMTSHA2H20D4W256, XMSSMTSHA2H40D2W256, XMSSMTSHA2H40D4W256,
		XMSSMTSHA2H40D8W256, XMSSMTSHA2H60D3W256, XMSSMTSHA2H60D6W256, XMSSMTSHA2H60D12W256,
		XMSSMTSHA2H20D2W512, XMSSMTSHA2H20D4W512, XMSSMTSHA2H40D2W512, XMSSMTSHA2H40D4W512,
		XMSSMTSHA2H40D8W512, XMSSMTSHA2H60D3W512, XMSSMTSHA2H60D6W512, XMSSMTSHA2H60D12W512,
		XMSSMTSHAKEH20D2W256, XMSSMTSHAKEH20D4W256, XMSSMTSHAKEH40D2W256, XMSSMTSHAKEH40D4W256,
		XMSSMTSHAKEH40D8W256, XMSSMTSHAKEH60D3W256, XMSSMTSHAKEH60D6W256, XMSSMTSHAKEH60D12W256,
		XMSSMTSHAKEH20D2W512, XMSSMTSHAKEH20D4W512, XMSSMTSHAKEH40D2W512, XMSSMTSHAKEH40D4W512,
		XMSSMTSHAKEH40D8W512, XMSSMTSHAKEH60D3W512, XMSSMTSHAKEH60D6W512, XMSSMTSHAKEH60D12W512}
	for i := 0; i < len(xmssmttys[1:2]); i++ {
		mtsk, mtpk, kerr := MTkeyGen(xmssmttys[i])
		if kerr != nil {
			t.Errorf("failed to generate key pair when XMSS-MT types = %x", xmssmttys[i])
		}
		if mtsk.Public().String() != mtpk.String() {
			t.Errorf("mtsk.Public() != mtpk when XMSS types = %x", xmssmttys[i])
		}
		for j := 0; j < 10; j++ {
			msg := make([]byte, 100)
			rand.Read(msg)
			mtsig, serr := mtsk.Sign(msg)
			if serr != nil {
				t.Errorf("failed to sign when XMSS-MT types = %x, j = %d", xmssmttys[i], j)
			}
			if !mtpk.Verify(msg, mtsig) {
				t.Errorf("invalid signature when XMSS-MT types = %x, j = %d", xmssmttys[i], j)
			}
		}
		smtsk, serr := ParseMTSK(mtsk.String())
		if serr != nil {
			t.Errorf("failed to parse private key when XMSS-MT types = %x", xmssmttys[i])
		}
		if smtsk.String() != mtsk.String() {
			t.Errorf("parsed xsk != xsk when XMSS-MT types = %x", xmssmttys[i])
		}
		smtpk, perr := ParseMTPK(mtpk.String())
		if perr != nil {
			t.Errorf("failed to parse public key when XMSS-MT types = %x", xmssmttys[i])
		}
		if smtpk.String() != mtpk.String() {
			t.Errorf("parsed xpk != xpk when XMSS types = %x", xmssmttys[i])
		}
		for j := 0; j < 5; j++ {
			msg := make([]byte, 100)
			rand.Read(msg)
			mtsig, _ := smtsk.Sign(msg)
			if !smtpk.Verify(msg, mtsig) {
				t.Errorf("invalid signature using parsed key pair when XMSS-MT types = %x, j = %d", xmssmttys[i], j)
			}
		}
	}
}
