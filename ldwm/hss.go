// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// A HSSPrivateKey represents a HSS private key.
type HSSPrivateKey struct {
	L       int
	lmspriv []*LMSPrivateKey
	lmspub  []*LMSPublicKey
	lmssign [][]byte
}

// A HSSPublicKey represents a HSS private key.
type HSSPublicKey struct {
	L      int
	lmspub *LMSPublicKey
}

// GenerateHSSPrivateKey generates a HSS private key.
func GenerateHSSPrivateKey(lmstypecode uint, otstypecode uint, L int) (*HSSPrivateKey, error) {
	if L < 1 || L > 8 {
		return nil, errors.New("hss: L should satisfy 1 <= L <= 8")
	}

	hsspriv := new(HSSPrivateKey)
	hsspriv.L = L
	hsspriv.lmspriv = make([]*LMSPrivateKey, L)
	hsspriv.lmspub = make([]*LMSPublicKey, L)
	hsspriv.lmssign = make([][]byte, L-1)

	for i := 0; i < L; i++ {
		hsspriv.lmspriv[i], _ = GenerateLMSPrivateKey(lmstypecode, otstypecode)
		hsspriv.lmspub[i], _ = hsspriv.lmspriv[i].Public()
	}

	for i := 0; i < L-1; i++ {
		hsspriv.lmssign[i], _ = hsspriv.lmspriv[i].Sign(hsspriv.lmspub[i+1].serialize())
	}

	return hsspriv, nil
}

func (hsspriv *HSSPrivateKey) String() string {
	str := string(u32str(hsspriv.L))
	for i := 0; i < hsspriv.L; i++ {
		str += string(hsspriv.lmspriv[i].serialize())
	}
	return fmt.Sprintf("%x", str)
}

// ParseHSSPrivateKey parses a HSS private key in hexadecimal.
func ParseHSSPrivateKey(keyhex string) (*HSSPrivateKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	if len(key) < 4 {
		return nil, errors.New("hss: (parse error) invalid HSS private key")
	}

	L := strTou32(key[:4])
	lmsprivlen := 4 + 4 + 4 + identifierLENGTH + hashLENGTH

	if len(key) != 4+lmsprivlen*L {
		return nil, errors.New("hss: (parse error) invalid HSS private key")
	}

	hsspriv := new(HSSPrivateKey)
	hsspriv.L = L
	hsspriv.lmspriv = make([]*LMSPrivateKey, L)
	hsspriv.lmspub = make([]*LMSPublicKey, L)
	hsspriv.lmssign = make([][]byte, L-1)

	for i := 0; i < L; i++ {
		lmspriv, err := parseLMSPrivateKey(key[4+lmsprivlen*i : 4+lmsprivlen*(i+1)])
		if err != nil {
			return nil, errors.New("hss: (parse error) invalid HSS private key")
		}
		hsspriv.lmspriv[i] = lmspriv
	}

	for i := 0; i < L; i++ {
		hsspriv.lmspub[i], _ = hsspriv.lmspriv[i].Public()
	}

	for i := 0; i < L-1; i++ {
		hsspriv.lmssign[i], _ = hsspriv.lmspriv[i].Sign(hsspriv.lmspub[i+1].serialize())
	}

	return hsspriv, nil
}

// Public generates the HSS public key.
func (hsspriv *HSSPrivateKey) Public() *HSSPublicKey {
	hsspub := new(HSSPublicKey)
	hsspub.L = hsspriv.L
	hsspub.lmspub = hsspriv.lmspub[0]
	return hsspub
}

func (hsspub *HSSPublicKey) String() string {
	str := string(u32str(hsspub.L)) + string(hsspub.lmspub.serialize())
	return fmt.Sprintf("%x", str)
}

// ParseHSSPublicKey parses a HSS public key in hexadecimal.
func ParseHSSPublicKey(keyhex string) (*HSSPublicKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	if len(key) < 5 {
		return nil, errors.New("hss: (parse error) invalid HSS public key")
	}

	L := strTou32(key[:4])
	hsspub := new(HSSPublicKey)
	hsspub.L = L
	hsspub.lmspub, err = parseLMSPublicKey(key[4:])
	if err != nil {
		return nil, errors.New("hss: (parse error) invalid HSS public key")
	}

	return hsspub, nil
}

// Sign generates an HSS signature for a message.
func (hsspriv *HSSPrivateKey) Sign(message []byte) ([]byte, error) {
	if len(hsspriv.lmspriv) != hsspriv.L ||
		len(hsspriv.lmspub) != hsspriv.L ||
		len(hsspriv.lmssign) != hsspriv.L-1 {
		return nil, errors.New("hss: invalid hss private key")
	}
	for hsspriv.lmspriv[len(hsspriv.lmspriv)-1].Validate() != nil {
		if len(hsspriv.lmspriv) == 1 {
			return nil, errors.New("hss: attempted overuse of hss private key")
		}
		hsspriv.lmspriv = hsspriv.lmspriv[:len(hsspriv.lmspriv)-1]
		hsspriv.lmspub = hsspriv.lmspub[:len(hsspriv.lmspub)-1]
		hsspriv.lmssign = hsspriv.lmssign[:len(hsspriv.lmssign)-1]
	}
	for len(hsspriv.lmspriv) < hsspriv.L {
		lmspriv, _ := GenerateLMSPrivateKey(hsspriv.lmspriv[0].lmstypecode, hsspriv.lmspriv[0].otstypecode)
		lmspub, _ := lmspriv.Public()
		hsspriv.lmspriv = append(hsspriv.lmspriv, lmspriv)
		hsspriv.lmspub = append(hsspriv.lmspub, lmspub)
		lmssign, _ := hsspriv.lmspriv[len(hsspriv.lmspriv)-2].Sign(lmspub.serialize())
		hsspriv.lmssign = append(hsspriv.lmssign, lmssign)
	}

	msign, err := hsspriv.lmspriv[len(hsspriv.lmspriv)-1].Sign(message)
	if err != nil {
		return nil, err
	}

	hsssign := make([]byte, 4)
	copy(hsssign, u32str(hsspriv.L-1))

	for i := 0; i < hsspriv.L-1; i++ {
		hsssign = append(hsssign, hsspriv.lmssign[i]...)
		hsssign = append(hsssign, hsspriv.lmspub[i+1].serialize()...)
	}

	hsssign = append(hsssign, msign...)

	return hsssign, nil
}

// Verify verifies a message with its HSS signature.
func (hsspub *HSSPublicKey) Verify(message, hsssign []byte) error {
	if len(hsssign) < 4 {
		return errors.New("hss: invalid HSS signature")
	}

	L := strTou32(hsssign[:4]) + 1
	if L != hsspub.L {
		return errors.New("hss: invalid HSS signature")
	}

	p := otstypes[hsspub.lmspub.otstypecode].p
	n := otstypes[hsspub.lmspub.otstypecode].n
	m := lmstypes[hsspub.lmspub.lmstypecode].m
	h := lmstypes[hsspub.lmspub.lmstypecode].h
	lmssignlen := 4 + (4 + n + n*p) + 4 + h*m
	lmspublen := 4 + 4 + identifierLENGTH + m

	if len(hsssign) != 4+lmssignlen*L+lmspublen*(L-1) {
		return errors.New("hss: invalid HSS signature")
	}

	lmspub := make([]*LMSPublicKey, L)
	lmssign := make([][]byte, L)

	lmspub[0] = hsspub.lmspub

	for i := 0; i < L-1; i++ {
		lmssign[i] = hsssign[4+(lmssignlen+lmspublen)*i : 4+(lmssignlen+lmspublen)*i+lmssignlen]
		tmppub, err := parseLMSPublicKey(hsssign[4+(lmssignlen+lmspublen)*i+lmssignlen : 4+(lmssignlen+lmspublen)*(i+1)])
		if err != nil {
			return errors.New("hss: invalid HSS signature")
		}
		lmspub[i+1] = tmppub
	}

	lmssign[L-1] = hsssign[len(hsssign)-lmssignlen:]

	for i := 0; i < L-1; i++ {
		err := lmspub[i].Verify(lmspub[i+1].serialize(), lmssign[i])
		if err != nil {
			return errors.New("hss: invalid HSS signature")
		}
	}

	err := lmspub[L-1].Verify(message, lmssign[L-1])
	if err != nil {
		return errors.New("hss: invalid HSS signature")
	}

	return nil
}
