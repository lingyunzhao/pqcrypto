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

// A LMSPrivateKey represents an LMS private key.
type LMSPrivateKey struct {
	height      int
	q           int
	lmstypecode uint
	otstypecode uint
	id          []byte
	root        []byte
	skseed      []byte
	authpath    [][]byte
	stacks      []*stack
}

// A LMSPublicKey represents an LMS public key.
type LMSPublicKey struct {
	lmstypecode uint   //LMS typecode
	otstypecode uint   //LM-OTS typecode
	id          []byte // a 16-byte identifier for the LMS public/private key pair
	t1          []byte
}

// GenerateLMSPrivateKey generates an LMS private key.
func GenerateLMSPrivateKey(lmstypecode uint, otstypecode uint) (*LMSPrivateKey, error) {
	if lmstypecode < LMSSHA256M32H5 || lmstypecode > LMSSHA256M32H25 {
		return nil, errors.New("lms: invalid LMS typecode")
	}

	I := make([]byte, identifierLENGTH)
	_, err := rand.Read(I)
	if err != nil {
		return nil, err
	}

	skseed := make([]byte, hashLENGTH)
	_, err = rand.Read(skseed)
	if err != nil {
		return nil, err
	}

	return genMTree(I, skseed, lmstypecode, otstypecode), nil
}

// Public generates the LMS public key.
func (lmspriv *LMSPrivateKey) Public() (*LMSPublicKey, error) {
	err := lmspriv.Validate()
	if err != nil {
		return nil, err
	}

	m := lmstypes[lmspriv.lmstypecode].m

	lmspub := new(LMSPublicKey)
	lmspub.lmstypecode = lmspriv.lmstypecode
	lmspub.otstypecode = lmspriv.otstypecode
	lmspub.id = make([]byte, identifierLENGTH)
	copy(lmspub.id, lmspriv.id)
	lmspub.t1 = make([]byte, m)
	copy(lmspub.t1, lmspriv.root)

	return lmspub, nil
}

// String serializes the private key and converts it to a hexadecimal string.
func (lmspriv *LMSPrivateKey) String() string {
	str := string(u32str(int(lmspriv.lmstypecode))) + string(u32str(int(lmspriv.otstypecode))) +
		string(u32str(lmspriv.q)) + string(lmspriv.id) + string(lmspriv.skseed)
	str = fmt.Sprintf("%x", str)
	return str
}

func (lmspriv *LMSPrivateKey) serialize() []byte {
	return bytes.Join([][]byte{u32str(int(lmspriv.lmstypecode)), u32str(int(lmspriv.otstypecode)),
		u32str(lmspriv.q), lmspriv.id, lmspriv.skseed}, []byte(""))
}

// String serializes the public key and converts it to a hexadecimal string.
func (lmspub *LMSPublicKey) String() string {
	return fmt.Sprintf("%x", string(u32str(int(lmspub.lmstypecode)))+
		string(u32str(int(lmspub.otstypecode)))+string(lmspub.id)+string(lmspub.t1))
}

func (lmspub *LMSPublicKey) serialize() []byte {
	return bytes.Join([][]byte{u32str(int(lmspub.lmstypecode)),
		u32str(int(lmspub.otstypecode)), lmspub.id, lmspub.t1}, []byte(""))
}

// ParseLMSPrivateKey parses an LMS private key from a hexadecimal string.
func ParseLMSPrivateKey(keyhex string) (*LMSPrivateKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	return parseLMSPrivateKey(key)
}

func parseLMSPrivateKey(key []byte) (*LMSPrivateKey, error) {

	if len(key) < 8 {
		return nil, errors.New("lms: (parse error) invalid LMS private key")
	}

	lmstypecode := uint(strTou32(key[:4]))
	otstypecode := uint(strTou32(key[4:8]))

	if len(key) != 4+4+4+identifierLENGTH+hashLENGTH {
		return nil, errors.New("lms: (parse error) invalid LMS private key")
	}
	q := strTou32(key[8:12])
	if lmstypecode < LMSSHA256M32H5 ||
		lmstypecode > LMSSHA256M32H25 ||
		q < 0 || q >= powInt(2, lmstypes[lmstypecode].h) ||
		otstypecode > LMOTSSHA256N32W8 {
		return nil, errors.New("lms: (parse error) invalid LMS private key")
	}

	I := key[12 : 12+identifierLENGTH]
	skseed := key[12+identifierLENGTH:]

	lmspriv := genMTree(I, skseed, lmstypecode, otstypecode)

	for i := 0; i < q; i++ {
		lmspriv.traversal()
	}

	return lmspriv, nil
}

// ParseLMSPublicKey parses an LMS public key from a hexadecimal string.
func ParseLMSPublicKey(keyhex string) (*LMSPublicKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	return parseLMSPublicKey(key)
}

func parseLMSPublicKey(key []byte) (*LMSPublicKey, error) {

	if len(key) <= 4+4+identifierLENGTH {
		return nil, errors.New("lms: (parse error) invalid LMS public key")
	}

	lmspub := new(LMSPublicKey)
	lmspub.lmstypecode = uint(strTou32(key[:4]))
	lmspub.otstypecode = uint(strTou32(key[4:8]))
	lmspub.id = make([]byte, identifierLENGTH)
	copy(lmspub.id, key[8:8+identifierLENGTH])
	lmspub.t1 = make([]byte, len(key)-(8+identifierLENGTH))
	copy(lmspub.t1, key[8+identifierLENGTH:])

	err := lmspub.Validate()
	if err != nil {
		return nil, errors.New("lms: (parse error) invalid LMS public key")
	}

	return lmspub, nil
}

// Sign generates an LMS signature from an LMS private key and a message, and updates the private key.
func (lmspriv *LMSPrivateKey) Sign(message []byte) ([]byte, error) {
	err := lmspriv.Validate()
	if err != nil {
		return nil, err
	}

	h := lmstypes[lmspriv.lmstypecode].h
	m := lmstypes[lmspriv.lmstypecode].m

	otspriv, _ := generateOTSPrivateKey(lmspriv.otstypecode, lmspriv.q, lmspriv.id, lmspriv.skseed)
	otssign, signerr := otspriv.Sign(message)
	if signerr != nil {
		return nil, err
	}

	path := make([]byte, h*m)
	for i := 0; i < h; i++ {
		copy(path[i*m:(i+1)*m], lmspriv.authpath[i])
	}
	lmspriv.traversal()

	return bytes.Join([][]byte{u32str(lmspriv.q - 1), otssign, u32str(int(lmspriv.lmstypecode)), path}, []byte("")), nil
}

// Verify verifies a message with its LMS signature.
func (lmspub *LMSPublicKey) Verify(message, lmssign []byte) error {
	err := lmspub.Validate()
	if err != nil {
		return err
	}

	Tc, tcerr := candidateLMSroot(message, lmssign, lmspub.id, lmspub.lmstypecode, lmspub.otstypecode)
	if tcerr != nil {
		return tcerr
	}

	if !bytes.Equal(Tc, lmspub.t1) {
		return errors.New("lms: invalid LMS signature")
	}

	return nil
}

// Computing an LMS public key candidate from a message, signature, identifier, and algorithm typecodes.
func candidateLMSroot(message []byte, lmssign []byte, I []byte, lmstypecode uint, otstypecode uint) ([]byte, error) {
	if len(lmssign) < 8 {
		return nil, errors.New("lms: invalid LMS signature")
	}

	q := strTou32(lmssign[:4])
	otssigntype := uint(strTou32(lmssign[4:8]))
	if otssigntype != otstypecode {
		return nil, errors.New("lms: invalid LMS signature")
	}

	n := otstypes[otssigntype].n
	p := otstypes[otssigntype].p

	if len(lmssign) < 12+n*(p+1) {
		return nil, errors.New("lms: invalid LMS signature")
	}

	otssign := lmssign[4 : 8+n*(p+1)]

	lmssigntype := uint(strTou32(lmssign[8+n*(p+1) : 12+n*(p+1)]))
	if lmssigntype != lmstypecode {
		return nil, errors.New("lms: invalid LMS signature")
	}

	m := lmstypes[lmssigntype].m
	h := lmstypes[lmssigntype].h

	if q < 0 || q >= powInt(2, h) || len(lmssign) != 12+n*(p+1)+m*h {
		return nil, errors.New("lms: invalid LMS signature")
	}

	path := lmssign[len(lmssign)-m*h:]

	Kc, err := otsKeyCandidate(message, otssign, otstypecode, I, q)
	if err != nil {
		return nil, err
	}

	node := powInt(2, h) + q
	tmp := hash(bytes.Join([][]byte{I, u32str(node), u16str(dLEAF), Kc}, []byte("")))
	for i := 0; node > 1; i = i + 1 {
		if node%2 == 1 {
			tmp = hash(bytes.Join([][]byte{I, u32str(int(node / 2)), u16str(dINTR), path[i*m : (i+1)*m], tmp}, []byte("")))
		} else {
			tmp = hash(bytes.Join([][]byte{I, u32str(int(node / 2)), u16str(dINTR), tmp, path[i*m : (i+1)*m]}, []byte("")))
		}
		node = int(node / 2)
	}

	return tmp[:], nil
}

// Validate performs basic sanity checks on the LMS private key.
// It returns nil if the LMS private key is valid, or else an error describing a problem.
func (lmspriv *LMSPrivateKey) Validate() error {
	if lmspriv.lmstypecode < LMSSHA256M32H5 ||
		lmspriv.lmstypecode > LMSSHA256M32H25 ||
		lmspriv.q < 0 || lmspriv.q >= powInt(2, lmstypes[lmspriv.lmstypecode].h) ||
		len(lmspriv.skseed) != hashLENGTH ||
		lmspriv.otstypecode > LMOTSSHA256N32W8 || len(lmspriv.id) != identifierLENGTH {
		return errors.New("lms: invalid LMS private key")
	}
	return nil
}

// Validate performs basic sanity checks on the LMS public key.
// It returns nil if the LMS public key is valid, or else an error describing a problem.
func (lmspub *LMSPublicKey) Validate() error {
	if lmspub.lmstypecode < LMSSHA256M32H5 ||
		lmspub.lmstypecode > LMSSHA256M32H25 ||
		lmspub.otstypecode > LMOTSSHA256N32W8 ||
		len(lmspub.id) != identifierLENGTH ||
		len(lmspub.t1) != lmstypes[lmspub.lmstypecode].m {
		return errors.New("lms: invalid LMS public key")
	}
	return nil
}
