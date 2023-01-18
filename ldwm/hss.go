// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// HSS private key.
type HssPrivateKey struct {
	layer   int
	lmsPriv []*LmsPrivateKey
	lmsPub  []*LmsPublicKey
	lmsSig  [][]byte
}

// HSS private key.
type HssPublicKey struct {
	layer  int
	lmsPub *LmsPublicKey
}

// Generates an HSS private key. The value of layer should satisfy 1 <= layer <= 8.
func GenerateHssPrivateKey(lmsTypecode uint, otsTypecode uint, layer int) (*HssPrivateKey, error) {
	if layer < 1 || layer > 8 {
		return nil, errors.New("hss: layer should satisfy 1 <= layer <= 8")
	}

	hssPriv := new(HssPrivateKey)
	hssPriv.layer = layer
	hssPriv.lmsPriv = make([]*LmsPrivateKey, layer)
	hssPriv.lmsPub = make([]*LmsPublicKey, layer)
	hssPriv.lmsSig = make([][]byte, layer-1)

	for i := 0; i < layer; i++ {
		hssPriv.lmsPriv[i], _ = GenerateLmsPrivateKey(lmsTypecode, otsTypecode)
		hssPriv.lmsPub[i], _ = hssPriv.lmsPriv[i].Public()
	}

	for i := 0; i < layer-1; i++ {
		hssPriv.lmsSig[i], _ = hssPriv.lmsPriv[i].Sign(hssPriv.lmsPub[i+1].serialize())
	}

	return hssPriv, nil
}

// Serializes the private key and converts it to a hexadecimal string.
func (hssPriv *HssPrivateKey) String() string {
	str := string(u32Str(hssPriv.layer))
	for i := 0; i < hssPriv.layer-1; i++ {
		hssPriv.lmsPriv[i].q--
		str += string(hssPriv.lmsPriv[i].serialize())
		hssPriv.lmsPriv[i].q++
	}
	str += string(hssPriv.lmsPriv[hssPriv.layer-1].serialize())
	return fmt.Sprintf("%x", str)
}

// Parses an HSS private key from a hexadecimal string.
func ParseHssPrivateKey(keyHex string) (*HssPrivateKey, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}

	if len(key) < 4 {
		return nil, errors.New("hss: (parse error) invalid HSS private key")
	}

	L := strTou32(key[:4])
	lmsPrivlen := 4 + 4 + 4 + IdentifierLength + HashLength

	if len(key) != 4+lmsPrivlen*L {
		return nil, errors.New("hss: (parse error) invalid HSS private key")
	}

	hssPriv := new(HssPrivateKey)
	hssPriv.layer = L
	hssPriv.lmsPriv = make([]*LmsPrivateKey, L)
	hssPriv.lmsPub = make([]*LmsPublicKey, L)
	hssPriv.lmsSig = make([][]byte, L-1)

	for i := 0; i < L; i++ {
		lmsPriv, err := parseLmsPrivateKey(key[4+lmsPrivlen*i : 4+lmsPrivlen*(i+1)])
		if err != nil {
			return nil, errors.New("hss: (parse error) invalid HSS private key")
		}
		hssPriv.lmsPriv[i] = lmsPriv
	}

	for i := 0; i < L; i++ {
		hssPriv.lmsPub[i], _ = hssPriv.lmsPriv[i].Public()
	}

	for i := 0; i < L-1; i++ {
		hssPriv.lmsSig[i], _ = hssPriv.lmsPriv[i].Sign(hssPriv.lmsPub[i+1].serialize())
	}

	return hssPriv, nil
}

// Generates the HSS public key.
func (hssPriv *HssPrivateKey) Public() *HssPublicKey {
	hssPub := new(HssPublicKey)
	hssPub.layer = hssPriv.layer
	hssPub.lmsPub = hssPriv.lmsPub[0]
	return hssPub
}

// Serializes the public key and converts it to a hexadecimal string.
func (hssPub *HssPublicKey) String() string {
	str := string(u32Str(hssPub.layer)) + string(hssPub.lmsPub.serialize())
	return fmt.Sprintf("%x", str)
}

// Parses an HSS public key from a hexadecimal string.
func ParseHssPublicKey(keyHex string) (*HssPublicKey, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}

	if len(key) < 5 {
		return nil, errors.New("hss: (parse error) invalid HSS public key")
	}

	L := strTou32(key[:4])
	hssPub := new(HssPublicKey)
	hssPub.layer = L
	hssPub.lmsPub, err = parseLmsPublicKey(key[4:])
	if err != nil {
		return nil, errors.New("hss: (parse error) invalid HSS public key")
	}

	return hssPub, nil
}

// Generates an HSS signature for a message and updates the private key.
func (hssPriv *HssPrivateKey) Sign(message []byte) ([]byte, error) {
	if len(hssPriv.lmsPriv) != hssPriv.layer ||
		len(hssPriv.lmsPub) != hssPriv.layer ||
		len(hssPriv.lmsSig) != hssPriv.layer-1 {
		return nil, errors.New("hss: invalid hss private key")
	}
	for hssPriv.lmsPriv[len(hssPriv.lmsPriv)-1].Validate() != nil {
		if len(hssPriv.lmsPriv) == 1 {
			return nil, errors.New("hss: attempted overuse of hss private key")
		}
		hssPriv.lmsPriv = hssPriv.lmsPriv[:len(hssPriv.lmsPriv)-1]
		hssPriv.lmsPub = hssPriv.lmsPub[:len(hssPriv.lmsPub)-1]
		hssPriv.lmsSig = hssPriv.lmsSig[:len(hssPriv.lmsSig)-1]
	}
	for len(hssPriv.lmsPriv) < hssPriv.layer {
		lmsPriv, _ := GenerateLmsPrivateKey(hssPriv.lmsPriv[0].lmsTypecode, hssPriv.lmsPriv[0].otsTypecode)
		lmsPub, _ := lmsPriv.Public()
		hssPriv.lmsPriv = append(hssPriv.lmsPriv, lmsPriv)
		hssPriv.lmsPub = append(hssPriv.lmsPub, lmsPub)
		lmsSig, _ := hssPriv.lmsPriv[len(hssPriv.lmsPriv)-2].Sign(lmsPub.serialize())
		hssPriv.lmsSig = append(hssPriv.lmsSig, lmsSig)
	}

	mSig, err := hssPriv.lmsPriv[len(hssPriv.lmsPriv)-1].Sign(message)
	if err != nil {
		return nil, err
	}

	hssSig := make([]byte, 4)
	copy(hssSig, u32Str(hssPriv.layer-1))

	for i := 0; i < hssPriv.layer-1; i++ {
		hssSig = append(hssSig, hssPriv.lmsSig[i]...)
		hssSig = append(hssSig, hssPriv.lmsPub[i+1].serialize()...)
	}

	hssSig = append(hssSig, mSig...)

	return hssSig, nil
}

// Verifies a message with its HSS signature.
func (hssPub *HssPublicKey) Verify(message, hssSig []byte) error {
	if len(hssSig) < 4 {
		return errors.New("hss: invalid HSS signature")
	}

	L := strTou32(hssSig[:4]) + 1
	if L != hssPub.layer {
		return errors.New("hss: invalid HSS signature")
	}
	hssSig = hssSig[4:]

	lmsPub := hssPub.lmsPub

	for i := 0; i < L-1; i++ {
		p := otsTypes[lmsPub.otsTypecode].p
		n := otsTypes[lmsPub.otsTypecode].n
		m := lmsTypes[lmsPub.lmsTypecode].m
		h := lmsTypes[lmsPub.lmsTypecode].h
		lmsSiglen := 4 + (4 + n + n*p) + 4 + h*m
		if len(hssSig) < lmsSiglen {
			return errors.New("hss: invalid HSS signature")
		}
		lmsSig := hssSig[:lmsSiglen]
		hssSig = hssSig[lmsSiglen:]
		if len(hssSig) < 8 {
			return errors.New("hss: invalid HSS signature")
		}
		nextLmsPubLen := 4 + 4 + IdentifierLength + lmsTypes[uint(strTou32(hssSig[:4]))].m
		if len(hssSig) < nextLmsPubLen {
			return errors.New("hss: invalid HSS signature")
		}
		nextLmsPub := hssSig[:nextLmsPubLen]
		hssSig = hssSig[nextLmsPubLen:]
		err := lmsPub.Verify(nextLmsPub, lmsSig)
		if err != nil {
			return errors.New("hss: invalid LMS signature")
		}
		lmsPub, err = parseLmsPublicKey(nextLmsPub)
		if err != nil {
			return errors.New("hss: invalid LMS public key")
		}
	}

	err := lmsPub.Verify(message, hssSig)
	if err != nil {
		return errors.New("hss: invalid LMS signature")
	}

	return nil
}
