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

// A MTSK represents an XMSS^MT private key.
type MTSK struct {
	oid      uint
	idx      uint64
	root     []byte
	seed     []byte
	skseed   []byte
	skprf    []byte
	xsk      []*SK
	chainsig [][]byte
}

func (mtsk *MTSK) serialize() []byte {
	mts := make([]byte, 0)
	for i := 0; i < len(mtsk.xsk); i++ {
		tmpmt := mtsk.xsk[i].mt.reducedSK()
		mts = append(mts, toByte(uint64(len(tmpmt)), 4)...)
		mts = append(mts, tmpmt...)
	}
	return bytes.Join([][]byte{toByte(uint64(mtsk.oid), 4), toByte(mtsk.idx, 8),
		mtsk.seed, mtsk.skseed, mtsk.skprf, mts, twoDto1D(mtsk.chainsig)}, []byte(""))
}

// String serializes the private key and converts it to a hexadecimal string.
func (mtsk *MTSK) String() string {
	return fmt.Sprintf("%x", mtsk.serialize())
}

// ParseMTSK parses an XMSS^MT private key in hexadecimal.
func ParseMTSK(sk string) (*MTSK, error) {
	skbytes, err := hex.DecodeString(sk)
	if err != nil {
		return nil, err
	}
	if len(skbytes) < 4+8 {
		return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
	}
	mtsk := new(MTSK)
	oid := strToUint(skbytes[:4])
	skbytes = skbytes[4:]
	if xmssmttypes[oid] == nil {
		return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
	}
	mtsk.oid = oid
	mtsk.idx = strToUint64(skbytes[:8])
	skbytes = skbytes[8:]
	xmssty := xmssmttypes[oid].xmssty
	d := xmssmttypes[oid].d
	n := xmsstypes[xmssty].n
	l := xmsstypes[xmssty].l
	xh := xmsstypes[xmssty].h
	if len(skbytes) < n+n+n {
		return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
	}
	mtsk.seed = make([]byte, n)
	copy(mtsk.seed, skbytes[:n])
	skbytes = skbytes[n:]
	mtsk.skseed = make([]byte, n)
	copy(mtsk.skseed, skbytes[:n])
	skbytes = skbytes[n:]
	mtsk.skprf = make([]byte, n)
	copy(mtsk.skprf, skbytes[:n])
	skbytes = skbytes[n:]

	mtsk.xsk = make([]*SK, d)
	for i := 0; i < d; i++ {
		if len(skbytes) < 4 {
			return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
		}
		sklen := strToInt(skbytes[:4])
		skbytes = skbytes[4:]
		if len(skbytes) < sklen {
			return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
		}
		mtsk.xsk[i] = parseReducedSK(skbytes[:sklen], i, mtsk.skseed, mtsk.seed, mtsk.skprf, xmssty)
		skbytes = skbytes[sklen:]
		if mtsk.xsk[i] == nil {
			return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
		}
	}

	if len(skbytes) != (xh+l)*n*(d-1) {
		return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
	}

	mtsk.chainsig = oneDto2D(skbytes, d-1, (xh+l)*n)
	mtsk.root = make([]byte, len(mtsk.xsk[d-1].mt.root))
	copy(mtsk.root, mtsk.xsk[d-1].mt.root)
	return mtsk, nil
}

// A MTPK represents an XMSS^MT public key.
type MTPK struct {
	oid  uint
	root []byte
	seed []byte
}

func (mtpk *MTPK) serialize() []byte {
	return bytes.Join([][]byte{toByte(uint64(mtpk.oid), 4), mtpk.root, mtpk.seed}, []byte(""))
}

// String serializes the public key and converts it to a hexadecimal string.
func (mtpk *MTPK) String() string {
	return fmt.Sprintf("%x", mtpk.serialize())
}

// ParseMTPK parses an XMSS^MT public key in hexadecimal.
func ParseMTPK(pk string) (*MTPK, error) {
	pkbytes, err := hex.DecodeString(pk)
	if err != nil {
		return nil, err
	}

	if len(pkbytes) < 4 {
		return nil, errors.New("xmss-mt: invalid XMSS^MT public key")
	}

	oid := strToUint(pkbytes[:4])
	if xmssmttypes[oid] == nil {
		return nil, errors.New("xmss-mt: invalid XMSS^MT public key")
	}
	n := xmsstypes[oid].n

	if len(pkbytes) != 4+n+n {
		return nil, errors.New("xmss-mt: invalid XMSS^MT public key")
	}

	mtpk := new(MTPK)
	mtpk.oid = oid
	mtpk.root = make([]byte, n)
	copy(mtpk.root, pkbytes[4:4+n])
	mtpk.seed = make([]byte, n)
	copy(mtpk.seed, pkbytes[4+n:4+n+n])

	return mtpk, nil
}

// MTkeyGen generates an XMSS^MT key pair
func MTkeyGen(oid uint) (*MTSK, *MTPK, error) {
	if xmssmttypes[oid] == nil {
		return nil, nil, errors.New("xmssmt: invalid XMSS^MT type")
	}
	mtsk := new(MTSK)

	n := xmsstypes[xmssmttypes[oid].xmssty].n

	mtsk.idx = 0
	mtsk.oid = oid
	mtsk.skprf = make([]byte, n)
	_, err := rand.Read(mtsk.skprf)
	if err != nil {
		return nil, nil, err
	}
	mtsk.seed = make([]byte, n)
	_, err = rand.Read(mtsk.seed)
	if err != nil {
		return nil, nil, err
	}
	mtsk.skseed = make([]byte, n)
	_, err = rand.Read(mtsk.skseed)
	if err != nil {
		return nil, nil, err
	}

	mtpk := new(MTPK)
	mtpk.oid = oid
	mtpk.seed = make([]byte, n)
	copy(mtpk.seed, mtsk.seed)

	d := xmssmttypes[oid].d
	mtsk.xsk = make([]*SK, d)
	for i := 0; i < d; i++ {
		mtsk.xsk[i], _, err = xmsskeyGen(xmssmttypes[oid].xmssty, mtsk.skseed, mtsk.seed, mtsk.skprf, i, 0)
		if err != nil {
			return nil, nil, err
		}
	}
	mtsk.root = make([]byte, len(mtsk.xsk[d-1].mt.root))
	copy(mtsk.root, mtsk.xsk[d-1].mt.root)
	mtpk.root = make([]byte, len(mtsk.xsk[d-1].mt.root))
	copy(mtpk.root, mtsk.xsk[d-1].mt.root)

	mtsk.chainsig = make([][]byte, d-1)
	adrs := toByte(0, 32)
	for i := d - 1; i > 0; i-- {
		set(adrs, int64(i), layeraddr)
		set(adrs, int64(mtsk.xsk[i].mt.idxtree), treeaddr)
		mtsk.chainsig[i-1] = twoDto1D(mtsk.xsk[i].treeSig(mtsk.xsk[i-1].mt.root, adrs))
	}

	return mtsk, mtpk, nil
}

// Public generates the public key of a private key.
func (mtsk *MTSK) Public() *MTPK {
	xpk := new(MTPK)
	xpk.oid = mtsk.oid
	xpk.root = make([]byte, len(mtsk.root))
	copy(xpk.root, mtsk.root)
	xpk.seed = make([]byte, len(mtsk.seed))
	copy(xpk.seed, mtsk.seed)
	return xpk
}

// Sign generates an XMSS^MT signature and updates the XMSS^MT private key.
func (mtsk *MTSK) Sign(message []byte) ([]byte, error) {
	if xmssmttypes[mtsk.oid] == nil {
		return nil, errors.New("xmss-mt: invalid XMSS^MT private key")
	}
	d := xmssmttypes[mtsk.oid].d
	xh := xmsstypes[xmssmttypes[mtsk.oid].xmssty].h
	if mtsk.xsk[d-1].mt.idx >= pow2(xh) {
		return nil, errors.New("xmss-mt: attempted overuse of XMSS^MT private key")
	}

	i := 0
	for ; i < d-1; i++ {
		if mtsk.xsk[i].mt.idx < pow2(xh) {
			break
		}
		tmpxsk, _, err := xmsskeyGen(xmssmttypes[mtsk.oid].xmssty, mtsk.skseed, mtsk.seed, mtsk.skprf, i, mtsk.xsk[i].mt.idx+1)
		if err != nil {
			return nil, err
		}
		mtsk.xsk[i] = tmpxsk
	}

	adrs := toByte(0, addrlen)

	for j := 1; j <= i; j++ {
		set(adrs, int64(j), layeraddr)
		set(adrs, int64(mtsk.xsk[j].mt.idxtree), treeaddr)
		mtsk.chainsig[j-1] = twoDto1D(mtsk.xsk[j].treeSig(mtsk.xsk[j-1].mt.root, adrs))
	}

	hsty := xmsstypes[xmssmttypes[mtsk.oid].xmssty].hsty
	n := xmsstypes[xmssmttypes[mtsk.oid].xmssty].n
	h := d * xh

	r := fn(toByte(mtsk.idx, 32), mtsk.skprf, hsty, prf)
	m := fn(message, bytes.Join([][]byte{r, mtsk.root, toByte(mtsk.idx, n)}, []byte("")), hsty, hmsg)

	mtsig := toByte(mtsk.idx, ceil(float64(h)/8))
	mtsig = append(mtsig, r...)

	set(adrs, 0, layeraddr)
	set(adrs, int64(mtsk.xsk[0].mt.idxtree), treeaddr)
	mtsig = append(mtsig, twoDto1D(mtsk.xsk[0].treeSig(m, adrs))...)
	mtsig = append(mtsig, twoDto1D(mtsk.chainsig)...)

	mtsk.idx++

	return mtsig, nil
}

// Verify  an XMSS^MT signature using the corresponding XMSS^MT public key and a message.
func (mtpk *MTPK) Verify(message, mtsig []byte) bool {
	if xmsstypes[mtpk.oid] == nil {
		return false
	}
	d := xmssmttypes[mtpk.oid].d
	xh := xmsstypes[xmssmttypes[mtpk.oid].xmssty].h
	l := xmsstypes[xmssmttypes[mtpk.oid].xmssty].l
	hsty := xmsstypes[xmssmttypes[mtpk.oid].xmssty].hsty
	wotspty := xmsstowotsp(xmssmttypes[mtpk.oid].xmssty)
	n := xmsstypes[xmssmttypes[mtpk.oid].xmssty].n
	h := d * xh
	idxsiglen := ceil(float64(h) / 8)
	if len(mtsig) != idxsiglen+n+(xh+l)*n*d {
		fmt.Println(len(mtsig), idxsiglen+n+(xh+l)*n*d)
		return false
	}
	idxsig := strToUint64(mtsig[:idxsiglen])
	r := mtsig[idxsiglen : idxsiglen+n]
	m := fn(message, bytes.Join([][]byte{r, mtpk.root, toByte(idxsig, n)}, []byte("")), hsty, hmsg)

	idxleaf := int(idxsig % uint64(pow2(xh)))
	idxtree := idxsig >> uint(xh)
	adrs := toByte(0, 32)
	set(adrs, 0, layeraddr)
	set(adrs, int64(idxtree), treeaddr)
	tmpsig := oneDto2D(mtsig[idxsiglen+n:idxsiglen+n+(xh+l)*n], xh+l, n)
	node := rootFromSig(m, mtpk.seed, tmpsig[:l], tmpsig[l:], adrs, idxleaf, wotspty, xh)
	for i := 1; i < d; i++ {
		idxleaf = int(idxtree % uint64(pow2(xh)))
		idxtree >>= uint(xh)
		tmpsig = oneDto2D(mtsig[idxsiglen+n+(xh+l)*n*i:idxsiglen+n+(xh+l)*n*(i+1)], xh+l, n)
		set(adrs, int64(i), layeraddr)
		set(adrs, int64(idxtree), treeaddr)
		node = rootFromSig(node, mtpk.seed, tmpsig[:l], tmpsig[l:], adrs, idxleaf, wotspty, xh)
	}
	if !bytes.Equal(mtpk.root, node) {
		return false
	}
	return true
}
