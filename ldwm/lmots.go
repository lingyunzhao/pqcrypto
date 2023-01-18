// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// LM-OTS private key.
type OtsPrivateKey struct {
	// LM-OTS typecode.
	otsTypecode uint
	// The 16-byte identifier of the LMS public/private key pair.
	id []byte

	// In the LMS N-time signature scheme, each LM-OTS signature is associated with
	// the leaf of a hash tree, and q is set to the leaf number.
	// When the LM-OTS signature system is used outside of an N-time signature system,
	// this value SHOULD be set to the all-zero value.
	q int

	seed []byte
	// p n-byte strings.
	x []byte
}

// LM-OTS public key.
type OtsPublicKey struct {
	// LM-OTS typecode.
	otsTypecode uint
	// The 16-byte identifier of the LMS public/private key pair.
	id []byte

	// In the LMS N-time signature scheme, each LM-OTS signature is associated with
	// the leaf of a hash tree, and q is set to the leaf number.
	// When the LM-OTS signature system is used outside of an N-time signature system,
	// this value SHOULD be set to the all-zero value.
	q int

	k []byte
}

// Generates an LM-OTS private key.
func GenerateOtsPrivateKey(otsTypecode uint) (*OtsPrivateKey, error) {
	I := make([]byte, IdentifierLength)
	_, err := rand.Read(I)
	if err != nil {
		return nil, err
	}

	seed := make([]byte, HashLength)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, err
	}

	return generateOtsPrivateKey(otsTypecode, 0, I, seed)
}

func generateOtsPrivateKey(otsTypecode uint, q int, I []byte, seed []byte) (*OtsPrivateKey, error) {
	if otsTypecode < LMOTS_SHA256_N32_W1 || otsTypecode > LMOTS_SHA256_N32_W8 {
		return nil, errors.New("lmots: invalid LM-OTS typecode")
	}
	otsPriv := new(OtsPrivateKey)
	otsPriv.otsTypecode = otsTypecode
	p := otsTypes[otsTypecode].p

	otsPriv.q = q

	if len(I) != IdentifierLength || len(seed) != HashLength {
		return nil, errors.New("lmots: invalid identifier I")
	}
	otsPriv.id = I
	otsPriv.seed = seed

	otsPriv.x = make([]byte, 0)
	hash := otsTypes[otsTypecode].hash
	for i := 0; i < p; i++ {
		tmp := hash(bytes.Join([][]byte{I, u32Str(q), u16Str(i), u8Str(0xff), seed}, []byte("")))
		otsPriv.x = append(otsPriv.x, tmp...)
	}

	return otsPriv, nil
}

// Generates the LM-OTS public key from private key.
func (otsPriv *OtsPrivateKey) Public() (*OtsPublicKey, error) {
	err := otsPriv.Validate()
	if err != nil {
		return nil, err
	}
	otsPub := new(OtsPublicKey)
	otsPub.otsTypecode = otsPriv.otsTypecode
	otsPub.id = otsPriv.id
	otsPub.q = otsPriv.q

	n := otsTypes[otsPub.otsTypecode].n
	p := otsTypes[otsPub.otsTypecode].p
	w := otsTypes[otsPub.otsTypecode].w

	// compute K
	y := make([]byte, p*n)
	hash := otsTypes[otsPub.otsTypecode].hash
	for i := 0; i < p; i++ {
		tmp := otsPriv.x[i*n : (i+1)*n]
		for j := 0; j < int(powInt(2, w)-1); j++ {
			tmp = hash(bytes.Join([][]byte{otsPub.id, u32Str(otsPub.q), u16Str(i), u8Str(j), tmp}, []byte("")))
		}
		copy(y[i*n:(i+1)*n], tmp)
	}
	otsPub.k = hash(bytes.Join([][]byte{otsPub.id, u32Str(otsPub.q), u16Str(D_PBLC), y}, []byte("")))

	return otsPub, nil
}

// Parses an LM-OTS public key from a hexadecimal string.
func ParseOtsPublicKey(keyHex string) (*OtsPublicKey, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}

	if len(key) < 4 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS public key")
	}

	otsPub := new(OtsPublicKey)
	otsTypecode := uint(strTou32(key[:4]))
	if otsTypecode > LMOTS_SHA256_N32_W8 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS public key")
	}
	otsPub.otsTypecode = otsTypecode
	n := otsTypes[otsTypecode].n

	if len(key) != 4+IdentifierLength+4+n {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS public key")
	}

	otsPub.id = key[4 : 4+IdentifierLength]
	otsPub.q = strTou32(key[4+IdentifierLength : 4+IdentifierLength+4])
	otsPub.k = key[4+IdentifierLength+4:]

	return otsPub, nil
}

// Parses an LM-OTS private key from a hexadecimal string.
func ParseOtsPrivateKey(keyhex string) (*OtsPrivateKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	if len(key) < 4 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS private key")
	}

	otsPriv := new(OtsPrivateKey)
	otsTypecode := uint(strTou32(key[:4]))
	if otsTypecode > LMOTS_SHA256_N32_W8 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS private key")
	}
	otsPriv.otsTypecode = otsTypecode
	p := otsTypes[otsTypecode].p

	if len(key) != 4+IdentifierLength+4+HashLength {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS private key")
	}

	otsPriv.id = key[4 : 4+IdentifierLength]
	otsPriv.q = strTou32(key[4+IdentifierLength : 4+IdentifierLength+4])
	otsPriv.seed = key[4+IdentifierLength+4:]

	otsPriv.x = make([]byte, 0)
	hash := otsTypes[otsTypecode].hash
	for i := 0; i < p; i++ {
		tmp := hash(bytes.Join([][]byte{otsPriv.id, u32Str(otsPriv.q), u16Str(i), u8Str(0xff), otsPriv.seed}, []byte("")))
		otsPriv.x = append(otsPriv.x, tmp...)
	}

	return otsPriv, nil
}

// Serializes the private key and converts it to a hexadecimal string.
func (otsPriv *OtsPrivateKey) String() string {
	return fmt.Sprintf("%x", strings.Join([]string{string(u32Str(int(otsPriv.otsTypecode))),
		string(otsPriv.id), string(u32Str(otsPriv.q)), string(otsPriv.seed)}, ""))
}

// Serializes the public key and converts it to a hexadecimal string.
func (otsPub *OtsPublicKey) String() string {
	return fmt.Sprintf("%x", strings.Join([]string{string(u32Str(int(otsPub.otsTypecode))),
		string(otsPub.id), string(u32Str(otsPub.q)), string(otsPub.k)}, ""))
}

// Performs basic sanity checks on the LM-OTS private key.
// Returns nil if the LM-OTS private key is valid, or else an error describing a problem.
func (otsPriv *OtsPrivateKey) Validate() error {
	switch {
	case otsPriv.otsTypecode > LMOTS_SHA256_N32_W8:
		return errors.New("lmots: invalid key params")
	case len(otsPriv.id) != 16:
		return errors.New("lmots: invalid identifier I")
	case otsPriv.q < 0:
		return errors.New("lmots: invalid leaf number q")
	case len(otsPriv.seed) != HashLength:
		return errors.New("lmots: invalid private key")
	case len(otsPriv.x) != otsTypes[otsPriv.otsTypecode].p*otsTypes[otsPriv.otsTypecode].n:
		return errors.New("lmots: invalid private key")
	}

	return nil
}

// Performs basic sanity checks on the LM-OTS public key.
// Returns nil if the LM-OTS public key is valid, or else an error describing a problem.
func (otsPub *OtsPublicKey) Validate() error {
	switch {
	case otsPub.otsTypecode > LMOTS_SHA256_N32_W8:
		return errors.New("lmots: invalid LM-OTS key params")
	case len(otsPub.id) != 16:
		return errors.New("lmots: invalid identifier I")
	case otsPub.q < 0:
		return errors.New("lmots: invalid leaf number q")
	case len(otsPub.k) != otsTypes[otsPub.otsTypecode].n:
		return errors.New("lmots: invalid LM-OTS private key")
	}

	return nil
}

// Generates a One Time Signature from an LM-OTS private key and a message.
func (otsPriv *OtsPrivateKey) Sign(message []byte) ([]byte, error) {
	err := otsPriv.Validate()
	if err != nil {
		return nil, err
	}

	w := otsTypes[otsPriv.otsTypecode].w
	p := otsTypes[otsPriv.otsTypecode].p
	ls := otsTypes[otsPriv.otsTypecode].ls
	n := otsTypes[otsPriv.otsTypecode].n

	C := make([]byte, n)
	_, err = rand.Read(C)
	if err != nil {
		return nil, err
	}

	hash := otsTypes[otsPriv.otsTypecode].hash
	Q := hash(bytes.Join([][]byte{otsPriv.id, u32Str(otsPriv.q), u16Str(D_MESG), C, message}, []byte("")))
	y := make([]byte, p*n)
	for i := 0; i < p; i++ {
		a := coef(append(Q, u16Str(cksm(Q, w, n, ls))...), i, w)
		tmp := otsPriv.x[i*n : (i+1)*n]
		for j := 0; j < a; j++ {
			tmp = hash(bytes.Join([][]byte{otsPriv.id, u32Str(otsPriv.q), u16Str(i), u8Str(j), tmp}, []byte("")))
		}
		copy(y[i*n:(i+1)*n], tmp)
	}

	return bytes.Join([][]byte{u32Str(int(otsPriv.otsTypecode)), C, y}, []byte("")), nil
}

// Verifies a message with its LM-OTS signature.
func (otsPub *OtsPublicKey) Verify(message, otsSig []byte) error {
	err := otsPub.Validate()
	if err != nil {
		return err
	}

	kc, kcErr := otsKeyCandidate(message, otsSig, otsPub.otsTypecode, otsPub.id, otsPub.q)
	if kcErr != nil {
		return kcErr
	}

	if !bytes.Equal(kc, otsPub.k) {
		return errors.New("lmots: invalid LM-OTS signature")
	}

	return nil
}

// Computes an LM-OTS public key candidate.
func otsKeyCandidate(message []byte, otsSig []byte, otsTypecode uint, I []byte, q int) ([]byte, error) {
	if len(otsSig) < 4 {
		return nil, errors.New("lmots: invalid LM-OTS signature")
	}

	otsSigType := uint(strTou32(otsSig[:4]))
	if otsSigType != otsTypecode {
		return nil, errors.New("lmots: invalid LM-OTS signature")
	}

	n := otsTypes[otsSigType].n
	p := otsTypes[otsSigType].p
	w := otsTypes[otsSigType].w
	ls := otsTypes[otsSigType].ls

	if len(otsSig) != 4+n*(p+1) {
		return nil, errors.New("lmots: invalid LM-OTS signature")
	}

	C := otsSig[4 : 4+n]
	y := otsSig[4+n:]

	//Compute Kc as follow
	hash := otsTypes[otsSigType].hash
	Q := hash(bytes.Join([][]byte{I, u32Str(q), u16Str(D_MESG), C, message}, []byte("")))
	z := make([]byte, p*n)
	for i := 0; i < p; i++ {
		a := coef(append(Q, u16Str(cksm(Q, w, n, ls))...), i, w)
		tmp := y[i*n : (i+1)*n]
		for j := a; j < powInt(2, w)-1; j++ {
			tmp = hash(bytes.Join([][]byte{I, u32Str(q), u16Str(i), u8Str(j), tmp}, []byte("")))
		}
		copy(z[i*n:(i+1)*n], tmp)
	}
	kc := hash(bytes.Join([][]byte{I, u32Str(q), u16Str(D_PBLC), z}, []byte("")))
	return kc, nil
}
