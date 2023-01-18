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
)

// LMS private key.
type LmsPrivateKey struct {
	height      int
	q           int
	lmsTypecode uint
	otsTypecode uint
	id          []byte
	root        []byte
	skSeed      []byte
	authPath    [][]byte
	stacks      []*stack
}

// LMS public key.
type LmsPublicKey struct {
	//LMS typecode.
	lmsTypecode uint
	//LM-OTS typecode.
	otsTypecode uint
	// The 16-byte identifier of the LMS public/private key pair.
	id []byte
	t1 []byte
}

// Geenerates an LMS private key.
func GenerateLmsPrivateKey(lmsTypecode uint, otsTypecode uint) (*LmsPrivateKey, error) {
	if lmsTypecode < LMS_SHA256_M32_H5 || lmsTypecode > LMS_SHA256_M32_H25 {
		return nil, errors.New("lms: invalid LMS typecode")
	}

	I := make([]byte, IdentifierLength)
	_, err := rand.Read(I)
	if err != nil {
		return nil, err
	}

	skSeed := make([]byte, HashLength)
	_, err = rand.Read(skSeed)
	if err != nil {
		return nil, err
	}

	return generateMerkleTree(I, skSeed, lmsTypecode, otsTypecode), nil
}

// Generates the LMS public key.
func (lmsPriv *LmsPrivateKey) Public() (*LmsPublicKey, error) {
	err := lmsPriv.Validate()
	if err != nil {
		return nil, err
	}

	lmsPub := new(LmsPublicKey)
	lmsPub.lmsTypecode = lmsPriv.lmsTypecode
	lmsPub.otsTypecode = lmsPriv.otsTypecode
	lmsPub.id = lmsPriv.id
	lmsPub.t1 = lmsPriv.root

	return lmsPub, nil
}

// Serializes the private key and converts it to a hexadecimal string.
func (lmsPriv *LmsPrivateKey) String() string {
	str := string(u32Str(int(lmsPriv.lmsTypecode))) + string(u32Str(int(lmsPriv.otsTypecode))) +
		string(u32Str(lmsPriv.q)) + string(lmsPriv.id) + string(lmsPriv.skSeed)
	str = fmt.Sprintf("%x", str)
	return str
}

func (lmsPriv *LmsPrivateKey) serialize() []byte {
	return bytes.Join([][]byte{u32Str(int(lmsPriv.lmsTypecode)), u32Str(int(lmsPriv.otsTypecode)),
		u32Str(lmsPriv.q), lmsPriv.id, lmsPriv.skSeed}, []byte(""))
}

// Serializes the public key and converts it to a hexadecimal string.
func (lmsPub *LmsPublicKey) String() string {
	return fmt.Sprintf("%x", string(u32Str(int(lmsPub.lmsTypecode)))+
		string(u32Str(int(lmsPub.otsTypecode)))+string(lmsPub.id)+string(lmsPub.t1))
}

func (lmsPub *LmsPublicKey) serialize() []byte {
	return bytes.Join([][]byte{u32Str(int(lmsPub.lmsTypecode)),
		u32Str(int(lmsPub.otsTypecode)), lmsPub.id, lmsPub.t1}, []byte(""))
}

// Parses an LMS private key from a hexadecimal string.
func ParseLmsPrivateKey(keyHex string) (*LmsPrivateKey, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}

	return parseLmsPrivateKey(key)
}

func parseLmsPrivateKey(key []byte) (*LmsPrivateKey, error) {

	if len(key) < 8 {
		return nil, errors.New("lms: (parse error) invalid LMS private key")
	}

	lmsTypecode := uint(strTou32(key[:4]))
	otsTypecode := uint(strTou32(key[4:8]))

	if len(key) != 4+4+4+IdentifierLength+HashLength {
		return nil, errors.New("lms: (parse error) invalid LMS private key")
	}
	q := strTou32(key[8:12])
	if lmsTypecode < LMS_SHA256_M32_H5 ||
		lmsTypecode > LMS_SHA256_M32_H25 ||
		q < 0 || q >= powInt(2, lmsTypes[lmsTypecode].h) ||
		otsTypecode > LMOTS_SHA256_N32_W8 {
		return nil, errors.New("lms: (parse error) invalid LMS private key")
	}

	I := key[12 : 12+IdentifierLength]
	skSeed := key[12+IdentifierLength:]

	lmsPriv := generateMerkleTree(I, skSeed, lmsTypecode, otsTypecode)

	for i := 0; i < q; i++ {
		lmsPriv.traversal()
	}

	return lmsPriv, nil
}

// Parses an LMS public key from a hexadecimal string.
func ParseLmsPublicKey(keyhex string) (*LmsPublicKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	return parseLmsPublicKey(key)
}

func parseLmsPublicKey(key []byte) (*LmsPublicKey, error) {

	if len(key) <= 4+4+IdentifierLength {
		return nil, errors.New("lms: (parse error) invalid LMS public key")
	}

	lmsPub := new(LmsPublicKey)
	lmsPub.lmsTypecode = uint(strTou32(key[:4]))
	lmsPub.otsTypecode = uint(strTou32(key[4:8]))
	lmsPub.id = key[8 : 8+IdentifierLength]
	lmsPub.t1 = key[8+IdentifierLength:]

	err := lmsPub.Validate()
	if err != nil {
		return nil, errors.New("lms: (parse error) invalid LMS public key")
	}

	return lmsPub, nil
}

// Generates an LMS signature from an LMS private key and a message, and updates the private key.
func (lmsPriv *LmsPrivateKey) Sign(message []byte) ([]byte, error) {
	err := lmsPriv.Validate()
	if err != nil {
		return nil, err
	}

	h := lmsTypes[lmsPriv.lmsTypecode].h
	m := lmsTypes[lmsPriv.lmsTypecode].m

	otsPriv, _ := generateOtsPrivateKey(lmsPriv.otsTypecode, lmsPriv.q, lmsPriv.id, lmsPriv.skSeed)
	otsSig, sigErr := otsPriv.Sign(message)
	if sigErr != nil {
		return nil, err
	}

	path := make([]byte, h*m)
	for i := 0; i < h; i++ {
		copy(path[i*m:(i+1)*m], lmsPriv.authPath[i])
	}
	lmsPriv.traversal()

	return bytes.Join([][]byte{u32Str(lmsPriv.q - 1), otsSig, u32Str(int(lmsPriv.lmsTypecode)), path}, []byte("")), nil
}

// Verifies a message with its LMS signature.
func (lmsPub *LmsPublicKey) Verify(message, lmsSig []byte) error {
	err := lmsPub.Validate()
	if err != nil {
		return err
	}

	tc, tcErr := candidateLmsRoot(message, lmsSig, lmsPub.id, lmsPub.lmsTypecode, lmsPub.otsTypecode)
	if tcErr != nil {
		return tcErr
	}

	if !bytes.Equal(tc, lmsPub.t1) {
		return errors.New("lms: invalid LMS signature")
	}

	return nil
}

// Computes an LMS public key candidate from a message, signature, identifier, and algorithm typecodes.
func candidateLmsRoot(message []byte, lmsSig []byte, I []byte, lmsTypecode uint, otsTypecode uint) ([]byte, error) {
	if len(lmsSig) < 8 {
		return nil, errors.New("lms: invalid LMS signature")
	}

	q := strTou32(lmsSig[:4])
	otsSigType := uint(strTou32(lmsSig[4:8]))
	if otsSigType != otsTypecode {
		return nil, errors.New("lms: invalid LMS signature")
	}

	n := otsTypes[otsSigType].n
	p := otsTypes[otsSigType].p

	if len(lmsSig) < 12+n*(p+1) {
		return nil, errors.New("lms: invalid LMS signature")
	}

	otsSig := lmsSig[4 : 8+n*(p+1)]

	lmsSigType := uint(strTou32(lmsSig[8+n*(p+1) : 12+n*(p+1)]))
	if lmsSigType != lmsTypecode {
		return nil, errors.New("lms: invalid LMS signature")
	}

	m := lmsTypes[lmsSigType].m
	h := lmsTypes[lmsSigType].h

	if q < 0 || q >= powInt(2, h) || len(lmsSig) != 12+n*(p+1)+m*h {
		return nil, errors.New("lms: invalid LMS signature")
	}

	path := lmsSig[len(lmsSig)-m*h:]

	kc, err := otsKeyCandidate(message, otsSig, otsTypecode, I, q)
	if err != nil {
		return nil, err
	}

	node := powInt(2, h) + q
	hash := lmsTypes[lmsSigType].hash
	tmp := hash(bytes.Join([][]byte{I, u32Str(node), u16Str(D_LEAF), kc}, []byte("")))
	for i := 0; node > 1; i = i + 1 {
		if node%2 == 1 {
			tmp = hash(bytes.Join([][]byte{I, u32Str(int(node / 2)), u16Str(D_INTR), path[i*m : (i+1)*m], tmp}, []byte("")))
		} else {
			tmp = hash(bytes.Join([][]byte{I, u32Str(int(node / 2)), u16Str(D_INTR), tmp, path[i*m : (i+1)*m]}, []byte("")))
		}
		node = int(node / 2)
	}

	return tmp[:], nil
}

// Performs basic sanity checks on the LMS private key.
// Returns nil if the LMS private key is valid, or else an error describing a problem.
func (lmsPriv *LmsPrivateKey) Validate() error {
	if lmsPriv.lmsTypecode < LMS_SHA256_M32_H5 ||
		lmsPriv.lmsTypecode > LMS_SHA256_M32_H25 ||
		lmsPriv.q < 0 || lmsPriv.q >= powInt(2, lmsTypes[lmsPriv.lmsTypecode].h) ||
		len(lmsPriv.skSeed) != HashLength ||
		lmsPriv.otsTypecode > LMOTS_SHA256_N32_W8 || len(lmsPriv.id) != IdentifierLength {
		return errors.New("lms: invalid LMS private key")
	}
	return nil
}

// Performs basic sanity checks on the LMS public key.
// Returns nil if the LMS public key is valid, or else an error describing a problem.
func (lmsPub *LmsPublicKey) Validate() error {
	if lmsPub.lmsTypecode < LMS_SHA256_M32_H5 ||
		lmsPub.lmsTypecode > LMS_SHA256_M32_H25 ||
		lmsPub.otsTypecode > LMOTS_SHA256_N32_W8 ||
		len(lmsPub.id) != IdentifierLength ||
		len(lmsPub.t1) != lmsTypes[lmsPub.lmsTypecode].m {
		return errors.New("lms: invalid LMS public key")
	}
	return nil
}
