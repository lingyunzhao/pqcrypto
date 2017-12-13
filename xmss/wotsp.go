// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"bytes"
	"errors"
)

// A wotspsk represents a WOTS+ private key.
type wotspsk struct {
	wotspty uint
	seed    []byte
	sk      [][]byte
}

// A wotsppk represents a WOTS+ public key.
type wotsppk struct {
	wotspty uint
	seed    []byte
	pk      [][]byte
}

// wotspGenSK generates a WOTS+ private key.
func wotspGenSK(seed []byte, wotspty uint) (*wotspsk, error) {
	// if wotspty < WOTSPSHA2W256 || wotspty > WOTSPSHAKE512 {
	// 	return nil, errors.New("wotsp: invalid WOTS+ type")
	// }
	// n := wotsptypes[wotspty].n
	if wotsptypes[wotspty] == nil {
		return nil, errors.New("wotsp: invalid WOTS+ type")
	}
	l := wotsptypes[wotspty].l
	hsty := wotsptypes[wotspty].hsty
	wsk := new(wotspsk)
	wsk.wotspty = wotspty
	wsk.seed = seed
	wsk.sk = make([][]byte, l)
	for i := 0; i < l; i++ {
		wsk.sk[i] = fn(toByte(uint64(i), 32), seed, hsty, prf)
	}
	return wsk, nil
}

func chain(x []byte, i int, s int, seed []byte, adrs address, wotspty uint) []byte {
	if s == 0 {
		return x
	}
	w := wotsptypes[wotspty].w
	if (i + s) > (w - 1) {
		return []byte{}
	}

	tmp := chain(x, i, s-1, seed, adrs, wotspty)
	hsty := wotsptypes[wotspty].hsty
	set(adrs, int64(i+s-1), hashaddr)
	set(adrs, 0, keyAndMask)
	key := fn(adrs, seed, hsty, prf)
	set(adrs, 1, keyAndMask)
	bm := fn(adrs, seed, hsty, prf)

	tmp = fn(xor(tmp, bm), key, hsty, f)
	set(adrs, 0, keyAndMask)
	set(adrs, 0, hashaddr)
	return tmp
}

// wotspGenPK generates the WOTS+ public key.
func (wsk *wotspsk) wotspGenPK(adrs address, seed []byte) *wotsppk {
	w := wotsptypes[wsk.wotspty].w
	l := wotsptypes[wsk.wotspty].l
	n := wotsptypes[wsk.wotspty].n
	wpk := new(wotsppk)
	wpk.wotspty = wsk.wotspty
	wpk.seed = make([]byte, n)
	copy(wpk.seed, seed)
	wpk.pk = make([][]byte, l)
	for i := 0; i < l; i++ {
		set(adrs, int64(i), chainaddr)
		wpk.pk[i] = chain(wsk.sk[i], 0, w-1, seed, adrs, wsk.wotspty)
	}
	set(adrs, 0, chainaddr)
	return wpk
}

func (wsk *wotspsk) sign(message []byte, adrs address, seed []byte) [][]byte {
	return sigortmppk(message, adrs, seed, wsk.sk, wsk.wotspty, computewotspsig)
}

func (wpk *wotsppk) verify(message []byte, adrs address, sig [][]byte) bool {
	tmpwpk := sigortmppk(message, adrs, wpk.seed, sig, wpk.wotspty, computewotsptmppk)
	if len(tmpwpk) != len(wpk.pk) {
		return false
	}
	for i := 0; i < len(tmpwpk); i++ {
		if !bytes.Equal(tmpwpk[i], wpk.pk[i]) {
			return false
		}
	}
	return true
}

func sigortmppk(message []byte, adrs address, seed []byte, sigorsk [][]byte, wotspty uint, ctype int) [][]byte {
	csum := 0
	w := wotsptypes[wotspty].w
	n := wotsptypes[wotspty].n
	l := wotsptypes[wotspty].l
	l1 := len1(w, n)
	l2 := len2(w, n)
	msg := basew(message, w, l1)
	for i := 0; i < l1; i++ {
		csum += w - 1 - msg[i]
	}

	csum <<= uint(8 - ((l2 * lg(w)) % 8))
	l2bytes := ceil(float64(l2*lg(w)) / 8)
	msg = append(msg, basew(toByte(uint64(csum), l2bytes), w, l2)...)
	sigortmppk := make([][]byte, l)
	for i := 0; i < l; i++ {
		set(adrs, int64(i), chainaddr)
		if ctype == computewotspsig {
			sigortmppk[i] = chain(sigorsk[i], 0, msg[i], seed, adrs, wotspty)
		} else if ctype == computewotsptmppk {
			sigortmppk[i] = chain(sigorsk[i], msg[i], w-1-msg[i], seed, adrs, wotspty)
		}
	}
	set(adrs, 0, chainaddr)
	// fmt.Printf("%x\n", adrs)
	return sigortmppk
}
