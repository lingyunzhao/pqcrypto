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
	LMOTSSHA256N32W1
	LMOTSSHA256N32W2
	LMOTSSHA256N32W4
	LMOTSSHA256N32W8
	LMSSHA256M32H5
	LMSSHA256M32H10
	LMSSHA256M32H15
	LMSSHA256M32H20
	LMSSHA256M32H25
)

const (
	// Domain separation parameter
	dPBLC = 0x8080
	dMESG = 0x8181
	dLEAF = 0x8282
	dINTR = 0x8383

	identifierLENGTH = 16
	hashLENGTH       = 32
)

type otstype struct {
	w  int  // the width (in bits) of the Winternitz coefficients; it is a member of the set { 1, 2, 4, 8 }
	p  int  // the number of n-byte string elements that make up the LM-OTS signature
	ls uint // the number of left-shift bits used in the checksum function cksm
	n  int  // the number of bytes of the output of the hash function
}

var otstypes = map[uint]*otstype{
	//     			 w   p  ls       n
	uint(LMOTSSHA256N32W1): {1, 265, 7, hashLENGTH},
	uint(LMOTSSHA256N32W2): {2, 133, 6, hashLENGTH},
	uint(LMOTSSHA256N32W4): {4, 67, 4, hashLENGTH},
	uint(LMOTSSHA256N32W8): {8, 34, 0, hashLENGTH},
}

type lmstype struct {
	m int //the number of bytes associated with each node
	h int //the height (number of levels - 1) in the tree
}

var lmstypes = map[uint]*lmstype{
	//			m           h
	uint(LMSSHA256M32H5):  {hashLENGTH, 5},
	uint(LMSSHA256M32H10): {hashLENGTH, 10},
	uint(LMSSHA256M32H15): {hashLENGTH, 15},
	uint(LMSSHA256M32H20): {hashLENGTH, 20},
	uint(LMSSHA256M32H25): {hashLENGTH, 25},
}

func u32str(i int) []byte {
	str := [4]byte{byte((i & 0xff000000) >> 24),
		byte((i & 0x00ff0000) >> 16),
		byte((i & 0x0000ff00) >> 8),
		byte(i & 0x000000ff)}
	return str[:]
}

func u16str(i int) []byte {
	str := [2]byte{byte((i & 0xff00) >> 8), byte(i & 0x00ff)}
	return str[:]
}

func u8str(i int) []byte {
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

func hash(message []byte) []byte {
	digest := sha256.Sum256(message)
	return digest[:]
}
