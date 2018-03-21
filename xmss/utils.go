// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"math"

	"golang.org/x/crypto/sha3"
)

// XMSS address types
const (
	otsAddr = iota
	ltreeAddr
	hashtreeAddr
)

// WOTS+ types
const (
	_ = iota
	wotspsha2w256
	wotspsha2w512
	wotspshake256
	wotspshake512
)

// XMSS types
const (
	_ = iota
	XMSSSHA2H10W256
	XMSSSHA2H16W256
	XMSSSHA2H20W256
	XMSSSHA2H10W512
	XMSSSHA2H16W512
	XMSSSHA2H20W512
	XMSSSHAKEH10W256
	XMSSSHAKEH16W256
	XMSSSHAKEH20W256
	XMSSSHAKEH10W512
	XMSSSHAKEH16W512
	XMSSSHAKEH20W512
	xmssSHA2H5W256
	xmssSHA2H5W512
	xmssSHAKEH5W256
	xmssSHAKEH5W512
)

// XMSS-MT types
const (
	_ = iota
	XMSSMTSHA2H20D2W256
	XMSSMTSHA2H20D4W256
	XMSSMTSHA2H40D2W256
	XMSSMTSHA2H40D4W256
	XMSSMTSHA2H40D8W256
	XMSSMTSHA2H60D3W256
	XMSSMTSHA2H60D6W256
	XMSSMTSHA2H60D12W256
	XMSSMTSHA2H20D2W512
	XMSSMTSHA2H20D4W512
	XMSSMTSHA2H40D2W512
	XMSSMTSHA2H40D4W512
	XMSSMTSHA2H40D8W512
	XMSSMTSHA2H60D3W512
	XMSSMTSHA2H60D6W512
	XMSSMTSHA2H60D12W512
	XMSSMTSHAKEH20D2W256
	XMSSMTSHAKEH20D4W256
	XMSSMTSHAKEH40D2W256
	XMSSMTSHAKEH40D4W256
	XMSSMTSHAKEH40D8W256
	XMSSMTSHAKEH60D3W256
	XMSSMTSHAKEH60D6W256
	XMSSMTSHAKEH60D12W256
	XMSSMTSHAKEH20D2W512
	XMSSMTSHAKEH20D4W512
	XMSSMTSHAKEH40D2W512
	XMSSMTSHAKEH40D4W512
	XMSSMTSHAKEH40D8W512
	XMSSMTSHAKEH60D3W512
	XMSSMTSHAKEH60D6W512
	XMSSMTSHAKEH60D12W512
)

type wotsptype struct {
	hsty int
	n    int
	w    int
	l    int
}

var wotsptypes = map[uint]*wotsptype{
	//                     F/PRF     n   w  len
	uint(wotspsha2w256): {sha2w256, 32, 16, 67},
	uint(wotspsha2w512): {sha2w512, 64, 16, 131},
	uint(wotspshake256): {shake128, 32, 16, 67},
	uint(wotspshake512): {shake256, 64, 16, 131},
}

type xmsstype struct {
	hsty int
	n    int
	w    int
	l    int
	h    int
}

var xmsstypes = map[uint]*xmsstype{
	//         Name        Functions   n   w  len  h
	uint(XMSSSHA2H10W256):  {sha2w256, 32, 16, 67, 10},
	uint(XMSSSHA2H16W256):  {sha2w256, 32, 16, 67, 16},
	uint(XMSSSHA2H20W256):  {sha2w256, 32, 16, 67, 20},
	uint(XMSSSHA2H10W512):  {sha2w512, 64, 16, 131, 10},
	uint(XMSSSHA2H16W512):  {sha2w512, 64, 16, 131, 16},
	uint(XMSSSHA2H20W512):  {sha2w512, 64, 16, 131, 20},
	uint(XMSSSHAKEH10W256): {shake128, 32, 16, 67, 10},
	uint(XMSSSHAKEH16W256): {shake128, 32, 16, 67, 16},
	uint(XMSSSHAKEH20W256): {shake128, 32, 16, 67, 20},
	uint(XMSSSHAKEH10W512): {shake256, 64, 16, 131, 10},
	uint(XMSSSHAKEH16W512): {shake256, 64, 16, 131, 16},
	uint(XMSSSHAKEH20W512): {shake256, 64, 16, 131, 20},
	uint(xmssSHA2H5W256):   {sha2w256, 32, 16, 67, 5},
	uint(xmssSHA2H5W512):   {sha2w512, 64, 16, 131, 5},
	uint(xmssSHAKEH5W256):  {shake128, 32, 16, 67, 5},
	uint(xmssSHAKEH5W512):  {shake256, 64, 16, 131, 5},
}

type xmssmttype struct {
	xmssty uint
	d      int
}

var xmssmttypes = map[uint]*xmssmttype{
	//                               XMSS types    d
	uint(XMSSMTSHA2H20D2W256):   {XMSSSHA2H10W256, 2},
	uint(XMSSMTSHA2H20D4W256):   {xmssSHA2H5W256, 4},
	uint(XMSSMTSHA2H40D2W256):   {XMSSSHA2H20W256, 2},
	uint(XMSSMTSHA2H40D4W256):   {XMSSSHA2H10W256, 4},
	uint(XMSSMTSHA2H40D8W256):   {xmssSHA2H5W256, 8},
	uint(XMSSMTSHA2H60D3W256):   {XMSSSHA2H20W256, 3},
	uint(XMSSMTSHA2H60D6W256):   {XMSSSHA2H10W256, 6},
	uint(XMSSMTSHA2H60D12W256):  {xmssSHA2H5W256, 12},
	uint(XMSSMTSHA2H20D2W512):   {XMSSSHA2H10W512, 2},
	uint(XMSSMTSHA2H20D4W512):   {xmssSHA2H5W512, 4},
	uint(XMSSMTSHA2H40D2W512):   {XMSSSHA2H20W512, 2},
	uint(XMSSMTSHA2H40D4W512):   {XMSSSHA2H10W512, 4},
	uint(XMSSMTSHA2H40D8W512):   {xmssSHA2H5W512, 8},
	uint(XMSSMTSHA2H60D3W512):   {XMSSSHA2H20W512, 3},
	uint(XMSSMTSHA2H60D6W512):   {XMSSSHA2H10W512, 6},
	uint(XMSSMTSHA2H60D12W512):  {xmssSHA2H5W512, 12},
	uint(XMSSMTSHAKEH20D2W256):  {XMSSSHAKEH10W256, 2},
	uint(XMSSMTSHAKEH20D4W256):  {xmssSHAKEH5W256, 4},
	uint(XMSSMTSHAKEH40D2W256):  {XMSSSHAKEH20W256, 2},
	uint(XMSSMTSHAKEH40D4W256):  {XMSSSHAKEH10W256, 4},
	uint(XMSSMTSHAKEH40D8W256):  {xmssSHAKEH5W256, 8},
	uint(XMSSMTSHAKEH60D3W256):  {XMSSSHAKEH20W256, 3},
	uint(XMSSMTSHAKEH60D6W256):  {XMSSSHAKEH10W256, 6},
	uint(XMSSMTSHAKEH60D12W256): {xmssSHAKEH5W256, 12},
	uint(XMSSMTSHAKEH20D2W512):  {XMSSSHAKEH10W512, 2},
	uint(XMSSMTSHAKEH20D4W512):  {xmssSHAKEH5W512, 4},
	uint(XMSSMTSHAKEH40D2W512):  {XMSSSHAKEH20W512, 2},
	uint(XMSSMTSHAKEH40D4W512):  {XMSSSHAKEH10W512, 4},
	uint(XMSSMTSHAKEH40D8W512):  {xmssSHAKEH5W512, 8},
	uint(XMSSMTSHAKEH60D3W512):  {XMSSSHAKEH20W512, 3},
	uint(XMSSMTSHAKEH60D6W512):  {XMSSSHAKEH10W512, 6},
	uint(XMSSMTSHAKEH60D12W512): {xmssSHAKEH5W512, 12},
}

// Hash types
const (
	sha2w256 = iota
	sha2w512
	shake128
	shake256
)

// Function types
const (
	f = iota
	h
	hmsg
	prf
)

const (
	computewotspsig = iota
	computewotsptmppk
)

func fn(message []byte, key []byte, hsty int, fnty int) []byte {
	switch hsty {
	case sha2w256:
		digest := sha256.Sum256(bytes.Join([][]byte{toByte(uint64(fnty), 32), key, message}, []byte("")))
		return digest[:]
	case sha2w512:
		digest := sha512.Sum512(bytes.Join([][]byte{toByte(uint64(fnty), 64), key, message}, []byte("")))
		return digest[:]
	case shake128:
		digest := make([]byte, 16)
		sha3.ShakeSum128(digest, bytes.Join([][]byte{toByte(uint64(fnty), 32), key, message}, []byte("")))
		return digest
	case shake256:
		digest := make([]byte, 16)
		sha3.ShakeSum256(digest, bytes.Join([][]byte{toByte(uint64(fnty), 64), key, message}, []byte("")))
		return digest
	}
	return nil
}

func toByte(x uint64, y int) []byte {
	z := make([]byte, y)
	for i := y - 1; i >= 0; i-- {
		z[i] = byte(x & 0xff)
		x >>= 8
	}
	return z
}

func basew(x []byte, w int, outlen int) []int {
	in := 0
	out := 0
	total := uint32(0)
	bits := 0
	basew := make([]int, outlen)

	for consumed := 0; consumed < outlen; consumed++ {
		if bits == 0 {
			total = uint32(x[in])
			in++
			bits += 8
		}
		bits -= lg(w)
		basew[out] = int(total>>uint(bits)) & (w - 1)
		out++
	}

	return basew
}

func xor(x, y []byte) []byte {
	z := make([]byte, len(x))
	for i := 0; i < len(x); i++ {
		z[i] = x[i] ^ y[i]
	}
	return z
}

func ceil(x float64) int {
	return int(math.Ceil(x))
}

func floor(x float64) int {
	return int(math.Floor(x))
}

func len1(w, n int) int {
	return ceil(float64(8*n) / math.Log2(float64(w)))
}

func len2(w, n int) int {
	return floor(math.Log2(float64(len1(w, n)*(w-1)))/math.Log2(float64(w))) + 1
}

func lg(w int) int {
	return int(math.Log2(float64(w)))
}

func pow2(x int) int {
	return int(math.Pow(2, float64(x)))
}

type address []byte

const addrlen = 32

const (
	layeraddr  = 0
	treeaddr   = 4
	addrtype   = 12
	otsaddr    = 16
	ltreeaddr  = 16
	padding    = 16
	chainaddr  = 20
	treeheight = 20
	hashaddr   = 24
	treeindex  = 24
	keyAndMask = 28
)

func set(adrs address, value int64, member int) {
	switch member {
	case treeaddr:
		h := int(value >> 32)
		l := int(value & 0xffffffff)
		copy(adrs[member:member+4], toByte(uint64(h), 4))
		copy(adrs[member+4:member+8], toByte(uint64(l), 4))
	default:
		copy(adrs[member:member+4], toByte(uint64(value), 4))
	}
	return
}

func get(adrs address, member int) int64 {
	value := int64(0)
	var str []byte
	switch member {
	case treeaddr:
		str = adrs[member : member+8]

	default:
		str = adrs[member : member+4]
	}
	for i := 0; i < len(str)-1; i++ {
		value += int64(str[i])
		value <<= 8
	}
	value += int64(str[len(str)-1])
	return value
}

func strToInt(str []byte) int {
	str = str[:4]
	i := int(str[0])<<24 +
		int(str[1])<<16 +
		int(str[2])<<8 +
		int(str[3])
	return i
}

func strToUint(str []byte) uint {
	str = str[:4]
	i := uint(str[0])<<24 +
		uint(str[1])<<16 +
		uint(str[2])<<8 +
		uint(str[3])
	return i
}

func strToUint64(str []byte) uint64 {
	x := uint64(0)
	for i := 0; i < len(str)-1; i++ {
		x += uint64(str[i])
		x <<= 8
	}
	x += uint64(str[len(str)-1])
	return x
}

func xmsstowotsp(xmssty uint) uint {
	switch xmssty {
	case XMSSSHA2H10W256, XMSSSHA2H16W256, XMSSSHA2H20W256, xmssSHA2H5W256:
		return wotspsha2w256
	case XMSSSHA2H10W512, XMSSSHA2H16W512, XMSSSHA2H20W512, xmssSHA2H5W512:
		return wotspsha2w512
	case XMSSSHAKEH10W256, XMSSSHAKEH16W256, XMSSSHAKEH20W256, xmssSHAKEH5W256:
		return wotspshake256
	case XMSSSHAKEH10W512, XMSSSHAKEH16W512, XMSSSHAKEH20W512, xmssSHAKEH5W512:
		return wotspshake512
	}
	return 0
}

func getseed(skseed []byte, adrs address, hsty int) []byte {
	set(adrs, 0, chainaddr)
	set(adrs, 0, hashaddr)
	set(adrs, 0, keyAndMask)
	return fn(adrs, skseed, hsty, prf)
}

func twoDto1D(x [][]byte) []byte {
	y := make([]byte, 0)
	for i := 0; i < len(x); i++ {
		y = append(y, x[i]...)
	}
	return y
}

func oneDto2D(x []byte, m int, n int) [][]byte {
	y := make([][]byte, m)
	for i := 0; i < m; i++ {
		y[i] = x[n*i : n*(i+1)]
	}
	return y
}
