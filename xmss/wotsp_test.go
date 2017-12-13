// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"crypto/rand"
	"testing"
        // "fmt"
)

func TestWOTSP(t *testing.T) {
	wotsptys := []uint{WOTSPSHA2W256, WOTSPSHA2W512, WOTSPSHAKE256, WOTSPSHAKE512}
	for i := 0; i < len(wotsptys); i++ {
                skseed := make([]byte, wotsptypes[wotsptys[i]].n)
        	rand.Read(skseed)
		wsk, _ := wotspGenSK(skseed,wotsptys[i])
		adrs := make([]byte, addrlen)
		msg := make([]byte, 64)
		rand.Read(adrs)
                rand.Read(msg)
		seed := make([]byte, wotsptypes[wotsptys[i]].n)
		rand.Read(seed)
		wpk := wsk.wotspGenPK(adrs, seed)
		sig := wsk.sign(msg, adrs, seed)
		if !wpk.verify(msg, adrs, sig) {
			t.Errorf("invalid signature when WOTS+ types = %x", wotsptys[i])
		}
	}
}
