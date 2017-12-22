// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// A SK represents an XMSS private key.
type SK struct {
	oid   uint
	skprf []byte
	mt    *merkle
}

// String serializes the private key and converts it to a hexadecimal string.
func (xsk *SK) String() string {
	return fmt.Sprintf("%x", xsk.serialize())
}

func (xsk *SK) serialize() []byte {
	return bytes.Join([][]byte{toByte(uint64(xsk.oid), 4), xsk.skprf, xsk.mt.serialize()}, []byte(""))
}

// ParseSK parses an XMSS private key in hexadecimal.
func ParseSK(sk string) (*SK, error) {
	skbytes, err := hex.DecodeString(sk)
	if err != nil {
		return nil, err
	}
	if len(skbytes) < 4 {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	xsk := new(SK)
	oid := strToUint(skbytes[:4])
	skbytes = skbytes[4:]
	if xmsstypes[oid] == nil {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	n := xmsstypes[oid].n
	if len(skbytes) < n {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	xsk.skprf = make([]byte, n)
	copy(xsk.skprf, skbytes[:n])
	skbytes = skbytes[n:]
	wotspty := xmsstowotsp(oid)
	hsty := xmsstypes[oid].hsty
	h := xmsstypes[oid].h
	xsk.mt = parsemerkle(skbytes, n, h, hsty, wotspty)
	if xsk.mt == nil {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	xsk.oid = oid
	return xsk, nil
}

// A PK represents an XMSS public key.
type PK struct {
	oid  uint
	root []byte
	seed []byte
}

func (xpk *PK) serialize() []byte {
	return bytes.Join([][]byte{toByte(uint64(xpk.oid), 4), xpk.root, xpk.seed}, []byte(""))
}

// String serializes the public key and converts it to a hexadecimal string.
func (xpk *PK) String() string {
	return fmt.Sprintf("%x", xpk.serialize())
}

// ParsePK parses an XMSS public key in hexadecimal.
func ParsePK(pk string) (*PK, error) {
	pkbytes, err := hex.DecodeString(pk)
	if err != nil {
		return nil, err
	}

	if len(pkbytes) < 4 {
		return nil, errors.New("xmss: invalid XMSS public key")
	}

	oid := strToUint(pkbytes[:4])
	if xmsstypes[oid] == nil {
		return nil, errors.New("xmss: invalid XMSS public key")
	}
	n := xmsstypes[oid].n

	if len(pkbytes) != 4+n+n {
		return nil, errors.New("xmss: invalid XMSS public key")
	}

	xpk := new(PK)
	xpk.oid = oid
	xpk.root = make([]byte, n)
	copy(xpk.root, pkbytes[4:4+n])
	xpk.seed = make([]byte, n)
	copy(xpk.seed, pkbytes[4+n:4+n+n])

	return xpk, nil
}

// KeyGen generates an XMSS key pair
func KeyGen(oid uint) (*SK, *PK, error) {
	if xmsstypes[oid] == nil {
		return nil, nil, errors.New("xmss: invalid XMSS oid")
	}
	n := xmsstypes[oid].n
	seed := make([]byte, n)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, nil, err
	}
	skseed := make([]byte, n)
	_, err = rand.Read(skseed)
	if err != nil {
		return nil, nil, err
	}
	skprf := make([]byte, n)
	_, err = rand.Read(skprf)
	if err != nil {
		return nil, nil, err
	}
	return xmsskeyGen(oid, skseed, seed, skprf, 0, 0)
}

// Public generates the public key of a private key.
func (xsk *SK) Public() *PK {
	xpk := new(PK)
	xpk.oid = xsk.oid
	xpk.root = make([]byte, len(xsk.mt.root))
	copy(xpk.root, xsk.mt.root)
	xpk.seed = make([]byte, len(xsk.mt.seed))
	copy(xpk.seed, xsk.mt.seed)
	return xpk
}

func xmsskeyGen(oid uint, skseed []byte, seed []byte, skprf []byte, layer int, idxtree int) (*SK, *PK, error) {
	xsk := new(SK)
	xsk.oid = oid
	h := xmsstypes[oid].h
	n := xmsstypes[oid].n
	hsty := xmsstypes[oid].hsty
	xsk.skprf = make([]byte, n)
	copy(xsk.skprf, skprf)
	xsk.mt = genMTree(h, skseed, seed, hsty, xmsstowotsp(oid), layer, idxtree)

	xpk := new(PK)
	xpk.oid = oid
	xpk.seed = make([]byte, n)
	xpk.root = make([]byte, len(xsk.mt.root))
	copy(xpk.root, xsk.mt.root)
	copy(xpk.seed, seed)

	return xsk, xpk, nil
}

// Sign generates an XMSS signature and updates the XMSS private key.
func (xsk *SK) Sign(message []byte) ([]byte, error) {
	if xmsstypes[xsk.oid] == nil {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	h := xmsstypes[xsk.oid].h
	if xsk.mt.idx >= pow2(h) {
		return nil, errors.New("xmss: attempted overuse of XMSS private key")
	}
	hsty := xsk.mt.hsty
	n := xmsstypes[xsk.oid].n
	r := fn(toByte(uint64(xsk.mt.idx), 32), xsk.skprf, hsty, prf)
	m := fn(message, bytes.Join([][]byte{r, xsk.mt.root, toByte(uint64(xsk.mt.idx), n)}, []byte("")), hsty, hmsg)
	adrs := toByte(0, addrlen)
	xsig := bytes.Join([][]byte{toByte(uint64(xsk.mt.idx), 4), r}, []byte(""))
	set(adrs, int64(xsk.mt.layer), layeraddr)
	set(adrs, int64(xsk.mt.idxtree), treeaddr)
	xsig = append(xsig, twoDto1D(xsk.treeSig(m, adrs))...)
	return xsig, nil
}

// Verify an XMSS signature using the corresponding XMSS public key and a message.
func (xpk *PK) Verify(message []byte, xsig []byte) bool {
	adrs := toByte(0, 32)
	set(adrs, 0, layeraddr)
	set(adrs, 0, treeaddr)
	hsty := xmsstypes[xpk.oid].hsty
	n := xmsstypes[xpk.oid].n
	l := xmsstypes[xpk.oid].l
	h := xmsstypes[xpk.oid].h
	if len(xsig) != 4+n+l*n+n*h {
		return false
	}
	idx := strToInt(xsig[:4])
	r := xsig[4 : 4+n]
	wsig := oneDto2D(xsig[4+n:4+n+n*l], l, n)
	authpath := oneDto2D(xsig[4+n+n*l:4+n+n*l+n*h], h, n)
	m := fn(message, bytes.Join([][]byte{r, xpk.root, toByte(uint64(idx), n)}, []byte("")), hsty, hmsg)
	root := rootFromSig(m, xpk.seed, wsig, authpath, adrs, idx, xmsstowotsp(xpk.oid), h)
	if !bytes.Equal(root, xpk.root) {
		return false
	}
	return true
}

func (xsk *SK) treeSig(m []byte, adrs address) [][]byte {
	set(adrs, otsAddr, addrtype)
	set(adrs, int64(xsk.mt.idx), otsaddr)
	wsk, _ := wotspGenSK(getseed(xsk.mt.skseed, adrs, xsk.mt.hsty), xmsstowotsp(xsk.oid))
	sig := wsk.sign(m, adrs, xsk.mt.seed)
	wsklen := len(sig)
	sig = append(sig, make([][]byte, len(xsk.mt.authpath))...)
	for i := 0; i < len(xsk.mt.authpath); i++ {
		sig[wsklen+i] = make([]byte, len(xsk.mt.authpath[i]))
		copy(sig[wsklen+i], xsk.mt.authpath[i])
	}
	if xsk.mt.idx == pow2(xmsstypes[xsk.oid].h)-1 {
		xsk.mt.idx++
	} else {
		xsk.mt.traversal()
	}
	return sig
}

func rootFromSig(m []byte, seed []byte, wsig [][]byte, authpath [][]byte, adrs address, idx int, wotspty uint, h int) []byte {
	set(adrs, otsAddr, addrtype)
	set(adrs, int64(idx), otsaddr)
	wpk := new(wotsppk)
	wpk.pk = sigortmppk(m, adrs, seed, wsig, wotspty, computewotsptmppk)
	wpk.wotspty = wotspty
	wpk.seed = seed
	set(adrs, ltreeAddr, addrtype)
	set(adrs, int64(idx), ltreeaddr)
	nd := wpk.ltree(adrs)
	set(adrs, hashtreeAddr, addrtype)
	set(adrs, int64(idx), treeindex)
	hsty := wotsptypes[wotspty].hsty
	for k := 0; k < h; k++ {
		set(adrs, int64(k), treeheight)
		if floor(float64(idx)/float64(pow2(k)))%2 == 0 {
			set(adrs, get(adrs, treeindex)/2, treeindex)
			nd = randhash(nd, authpath[k], seed, adrs, hsty)
		} else {
			set(adrs, (get(adrs, treeindex)-1)/2, treeindex)
			nd = randhash(authpath[k], nd, seed, adrs, hsty)
		}
	}
	return nd
}

func randhash(left []byte, right []byte, seed []byte, adrs address, hsty int) []byte {
	set(adrs, 0, keyAndMask)
	key := fn(adrs, seed, hsty, prf)
	set(adrs, 1, keyAndMask)
	bm0 := fn(adrs, seed, hsty, prf)
	set(adrs, 2, keyAndMask)
	bm1 := fn(adrs, seed, hsty, prf)
	set(adrs, 0, keyAndMask)

	return fn(append(xor(left, bm0), xor(right, bm1)...), key, hsty, h)
}

func (wpk *wotsppk) ltree(adrs address) []byte {
	l := wotsptypes[wpk.wotspty].l
	hsty := wotsptypes[wpk.wotspty].hsty
	set(adrs, 0, treeheight)
	for l > 1 {
		for i := 0; i < floor(float64(l)/2); i++ {
			set(adrs, int64(i), treeindex)
			wpk.pk[i] = randhash(wpk.pk[2*i], wpk.pk[2*i+1], wpk.seed, adrs, hsty)
		}
		if l&0x01 == 1 {
			copy(wpk.pk[floor(float64(l)/2)], wpk.pk[l-1])
		}
		l = ceil(float64(l) / 2)
		set(adrs, get(adrs, treeheight)+1, treeheight)
	}
	set(adrs, 0, treeheight)
	set(adrs, 0, treeindex)
	set(adrs, 0, ltreeaddr)
	return wpk.pk[0]
}
