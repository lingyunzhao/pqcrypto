// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"crypto/sha256"
	"math"
)

// LM-OTS types
const (
	_ = iota
	LMOTS_SHA256_N32_W1
	LMOTS_SHA256_N32_W2
	LMOTS_SHA256_N32_W4
	LMOTS_SHA256_N32_W8
)

// LMS types
const (
	_ = iota + 4
	LMS_SHA256_M32_H5
	LMS_SHA256_M32_H10
	LMS_SHA256_M32_H15
	LMS_SHA256_M32_H20
	LMS_SHA256_M32_H25
)

const (
	// Domain separation parameters
	D_PBLC = 0x8080
	D_MESG = 0x8181
	D_LEAF = 0x8282
	D_INTR = 0x8383

	IdentifierLength = 16
	HashLength       = 32
)

type otsType struct {
	// The width (in bits) of the Winternitz coefficients; it is a member of the set { 1, 2, 4, 8 }.
	w int
	// The number of n-byte string elements that make up the LM-OTS signature.
	p int
	// The number of left-shift bits used in the checksum function cksm.
	ls uint
	// The number of bytes of the output of the hash function.
	n    int
	hash func([]byte) []byte
}

var otsTypes = map[uint]*otsType{
	uint(LMOTS_SHA256_N32_W1): {1, 265, 7, sha256.Size, sha256Hash},
	uint(LMOTS_SHA256_N32_W2): {2, 133, 6, sha256.Size, sha256Hash},
	uint(LMOTS_SHA256_N32_W4): {4, 67, 4, sha256.Size, sha256Hash},
	uint(LMOTS_SHA256_N32_W8): {8, 34, 0, sha256.Size, sha256Hash},
}

type lmsType struct {
	//The number of bytes associated with each node.
	m int
	//The height (number of levels - 1) in the tree.
	h    int
	hash func([]byte) []byte
}

var lmsTypes = map[uint]*lmsType{
	uint(LMS_SHA256_M32_H5):  {sha256.Size, 5, sha256Hash},
	uint(LMS_SHA256_M32_H10): {sha256.Size, 10, sha256Hash},
	uint(LMS_SHA256_M32_H15): {sha256.Size, 15, sha256Hash},
	uint(LMS_SHA256_M32_H20): {sha256.Size, 20, sha256Hash},
	uint(LMS_SHA256_M32_H25): {sha256.Size, 25, sha256Hash},
}

func u32Str(i int) []byte {
	str := [4]byte{byte((i & 0xff000000) >> 24),
		byte((i & 0x00ff0000) >> 16),
		byte((i & 0x0000ff00) >> 8),
		byte(i & 0x000000ff)}
	return str[:]
}

func u16Str(i int) []byte {
	str := [2]byte{byte((i & 0xff00) >> 8), byte(i & 0x00ff)}
	return str[:]
}

func u8Str(i int) []byte {
	str := [1]byte{byte(i & 0xff)}
	return str[:]
}

func coef(s []byte, i int, w int) int {
	return int(powInt(2, w)-1) &
		(int(s[int(math.Floor(float64(i*w/8)))]) >> uint(8-(w*(i%(8/w))+w)))
}

func powInt(a, b int) int {
	return int(math.Pow(float64(a), float64(b)))
}

func cksm(s []byte, w int, n int, ls uint) int {
	sum := 0
	for i := 0; i < int(n*8/w); i++ {
		sum += powInt(2, w) - 1 - coef(s, i, w)
	}
	return sum << ls
}

func strTou32(str []byte) int {
	str = str[:4]
	i := int(str[0])<<24 +
		int(str[1])<<16 +
		int(str[2])<<8 +
		int(str[3])
	return i
}

func sibing(i int) int {
	if i%2 == 0 {
		return i + 1
	}
	return i - 1

}

func sha256Hash(message []byte) []byte {
	digest := sha256.Sum256(message)
	return digest[:]
}
