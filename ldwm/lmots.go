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

// A OTSPrivateKey represents a LM-OTS private key.
type OTSPrivateKey struct {
	otstypecode uint   // LM-OTS typecode
	id          []byte // a 16-byte identifier for the LMS public/private key pair

	// In the LMS N-time signature scheme, each LM-OTS signature is associated with
	// the leaf of a hash tree, and q is set to the leaf number.
	// When the LM-OTS signature system is used outside of an N-time signature system,
	// this value SHOULD be set to the all-zero value.
	q int

	seed []byte

	x []byte // p n-byte strings
}

// A OTSPublicKey represents a LM-OTS public key.
type OTSPublicKey struct {
	otstypecode uint   // LM-OTS typecode
	id          []byte // a 16-byte identifier for the LMS public/private key pair

	// In the LMS N-time signature scheme, each LM-OTS signature is associated with
	// the leaf of a hash tree, and q is set to the leaf number.
	// When the LM-OTS signature system is used outside of an N-time signature system,
	// this value SHOULD be set to the all-zero value.
	q int

	k []byte
}

// GenerateOTSPrivateKey generates a LM-OTS private key.
func GenerateOTSPrivateKey(otstypecode uint) (*OTSPrivateKey, error) {
	I := make([]byte, identifierLENGTH)
	_, err := rand.Read(I)
	if err != nil {
		return nil, err
	}

	seed := make([]byte, hashLENGTH)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, err
	}

	return generateOTSPrivateKey(otstypecode, 0, I, seed)
}

func generateOTSPrivateKey(otstypecode uint, q int, I []byte, seed []byte) (*OTSPrivateKey, error) {
	if otstypecode < LMOTSSHA256N32W1 || otstypecode > LMOTSSHA256N32W8 {
		return nil, errors.New("lmots: invalid LM-OTS typecode")
	}
	otspriv := new(OTSPrivateKey)
	otspriv.otstypecode = otstypecode
	p := otstypes[otstypecode].p

	otspriv.q = q

	if len(I) != identifierLENGTH || len(seed) != hashLENGTH {
		return nil, errors.New("lmots: invalid identifier I")
	}
	otspriv.id = make([]byte, identifierLENGTH)
	copy(otspriv.id, I)
	otspriv.seed = make([]byte, hashLENGTH)
	copy(otspriv.seed, seed)

	otspriv.x = make([]byte, 0)
	for i := 0; i < p; i++ {
		tmp := hash(bytes.Join([][]byte{I, u32str(q), u16str(i), u8str(0xff), seed}, []byte("")))
		otspriv.x = append(otspriv.x, tmp...)
	}
	// _, err := rand.Read(otspriv.x)
	// if err != nil {
	// 	return nil, err
	// }

	return otspriv, nil
}

// Public generates the LM-OTS public key from private key.
func (otspriv *OTSPrivateKey) Public() (*OTSPublicKey, error) {
	err := otspriv.Validate()
	if err != nil {
		return nil, err
	}
	otspub := new(OTSPublicKey)
	otspub.otstypecode = otspriv.otstypecode
	otspub.id = make([]byte, identifierLENGTH)
	copy(otspub.id, otspriv.id)
	otspub.q = otspriv.q

	n := otstypes[otspub.otstypecode].n
	p := otstypes[otspub.otstypecode].p
	w := otstypes[otspub.otstypecode].w

	// compute K
	y := make([]byte, p*n)
	for i := 0; i < p; i++ {
		tmp := make([]byte, n)
		copy(tmp, otspriv.x[i*n:(i+1)*n])
		for j := 0; j < int(powInt(2, w)-1); j++ {
			tmp = hash(bytes.Join([][]byte{otspub.id, u32str(otspub.q), u16str(i), u8str(j), tmp}, []byte("")))
		}
		copy(y[i*n:(i+1)*n], tmp)
	}
	otspub.k = hash(bytes.Join([][]byte{otspub.id, u32str(otspub.q), u16str(dPBLC), y}, []byte("")))

	return otspub, nil
}

// ParseOTSPublicKey parses a LM-OTS public key from a hexadecimal string.
func ParseOTSPublicKey(keyhex string) (*OTSPublicKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	if len(key) < 4 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS public key")
	}

	otspub := new(OTSPublicKey)
	otstypecode := uint(strTou32(key[:4]))
	if otstypecode > LMOTSSHA256N32W8 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS public key")
	}
	otspub.otstypecode = otstypecode
	n := otstypes[otstypecode].n

	if len(key) != 4+identifierLENGTH+4+n {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS public key")
	}

	otspub.id = make([]byte, identifierLENGTH)
	copy(otspub.id, key[4:4+identifierLENGTH])
	otspub.q = strTou32(key[4+identifierLENGTH : 4+identifierLENGTH+4])
	otspub.k = make([]byte, n)
	copy(otspub.k, key[4+identifierLENGTH+4:])

	return otspub, nil
}

// ParseOTSPrivateKey parses a LM-OTS private key from a hexadecimal string.
func ParseOTSPrivateKey(keyhex string) (*OTSPrivateKey, error) {
	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return nil, err
	}

	if len(key) < 4 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS private key")
	}

	otspriv := new(OTSPrivateKey)
	otstypecode := uint(strTou32(key[:4]))
	if otstypecode > LMOTSSHA256N32W8 {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS private key")
	}
	otspriv.otstypecode = otstypecode
	p := otstypes[otstypecode].p

	if len(key) != 4+identifierLENGTH+4+hashLENGTH {
		return nil, errors.New("lmots: (parse error) invalid LM-OTS private key")
	}

	otspriv.id = make([]byte, identifierLENGTH)
	copy(otspriv.id, key[4:4+identifierLENGTH])
	otspriv.q = strTou32(key[4+identifierLENGTH : 4+identifierLENGTH+4])
	otspriv.seed = make([]byte, hashLENGTH)
	copy(otspriv.seed, key[4+identifierLENGTH+4:])

	otspriv.x = make([]byte, 0)
	for i := 0; i < p; i++ {
		tmp := hash(bytes.Join([][]byte{otspriv.id, u32str(otspriv.q), u16str(i), u8str(0xff), otspriv.seed}, []byte("")))
		otspriv.x = append(otspriv.x, tmp...)
	}

	return otspriv, nil
}

// String serializes the private key and converts it to a hexadecimal string.
func (otspriv *OTSPrivateKey) String() string {
	return fmt.Sprintf("%x", strings.Join([]string{string(u32str(int(otspriv.otstypecode))),
		string(otspriv.id), string(u32str(otspriv.q)), string(otspriv.seed)}, ""))
}

// String serializes the public key and converts it to a hexadecimal string.
func (otspub *OTSPublicKey) String() string {
	return fmt.Sprintf("%x", strings.Join([]string{string(u32str(int(otspub.otstypecode))),
		string(otspub.id), string(u32str(otspub.q)), string(otspub.k)}, ""))
}

// func (otspub *OTSPublicKey) serialize() []byte {
// 	return bytes.Join([][]byte{u32str(int(otspub.otstypecode)),
// 		otspub.I, u32str(otspub.q), otspub.K}, []byte(""))
// }

// Validate performs basic sanity checks on the LM-OTS private key.
// It returns nil if the LM-OTS private key is valid, or else an error describing a problem.
func (otspriv *OTSPrivateKey) Validate() error {
	switch {
	case otspriv.otstypecode > LMOTSSHA256N32W8:
		return errors.New("lmots: invalid key params")
	case len(otspriv.id) != 16:
		return errors.New("lmots: invalid identifier I")
	case otspriv.q < 0:
		return errors.New("lmots: invalid leaf number q")
	case len(otspriv.seed) != hashLENGTH:
		return errors.New("lmots: invalid private key")
	case len(otspriv.x) != otstypes[otspriv.otstypecode].p*otstypes[otspriv.otstypecode].n:
		return errors.New("lmots: invalid private key")
	}

	return nil
}

// Validate performs basic sanity checks on the LM-OTS public key.
// It returns nil if the LM-OTS public key is valid, or else an error describing a problem.
func (otspub *OTSPublicKey) Validate() error {
	switch {
	case otspub.otstypecode > LMOTSSHA256N32W8:
		return errors.New("lmots: invalid LM-OTS key params")
	case len(otspub.id) != 16:
		return errors.New("lmots: invalid identifier I")
	case otspub.q < 0:
		return errors.New("lmots: invalid leaf number q")
	case len(otspub.k) != otstypes[otspub.otstypecode].n:
		return errors.New("lmots: invalid LM-OTS private key")
	}

	return nil
}

// Sign generates a One Time Signature from a LM-OTS private key and a message.
func (otspriv *OTSPrivateKey) Sign(message []byte) ([]byte, error) {
	err := otspriv.Validate()
	if err != nil {
		return nil, err
	}

	w := otstypes[otspriv.otstypecode].w
	p := otstypes[otspriv.otstypecode].p
	ls := otstypes[otspriv.otstypecode].ls
	n := otstypes[otspriv.otstypecode].n

	C := make([]byte, n)
	_, err = rand.Read(C)
	if err != nil {
		return nil, err
	}

	Q := hash(bytes.Join([][]byte{otspriv.id, u32str(otspriv.q), u16str(dMESG), C, message}, []byte("")))
	y := make([]byte, p*n)
	for i := 0; i < p; i++ {
		a := coef(append(Q, u16str(cksm(Q, w, n, ls))...), i, w)
		tmp := make([]byte, n)
		copy(tmp, otspriv.x[i*n:(i+1)*n])
		for j := 0; j < a; j++ {
			tmp = hash(bytes.Join([][]byte{otspriv.id, u32str(otspriv.q), u16str(i), u8str(j), tmp}, []byte("")))
		}
		copy(y[i*n:(i+1)*n], tmp)
	}

	return bytes.Join([][]byte{u32str(int(otspriv.otstypecode)), C, y}, []byte("")), nil
}

// Verify verifies a message with its LM-OTS signature.
func (otspub *OTSPublicKey) Verify(message, otssign []byte) error {
	err := otspub.Validate()
	if err != nil {
		return err
	}

	Kc, kcerr := otsKeyCandidate(message, otssign, otspub.otstypecode, otspub.id, otspub.q)
	if kcerr != nil {
		return kcerr
	}

	if !bytes.Equal(Kc, otspub.k) {
		return errors.New("lmots: invalid LM-OTS signature")
	}

	return nil
}

// Computing a LM-OTS public key candidate Kc from a LM-OTS message, signature, otstypecode, identifier and q.
func otsKeyCandidate(message []byte, otssign []byte, otstypecode uint, I []byte, q int) ([]byte, error) {
	if len(otssign) < 4 {
		return nil, errors.New("lmots: invalid LM-OTS signature")
	}

	otssigntype := uint(strTou32(otssign[:4]))
	if otssigntype != otstypecode {
		return nil, errors.New("lmots: invalid LM-OTS signature")
	}

	n := otstypes[otssigntype].n
	p := otstypes[otssigntype].p
	w := otstypes[otssigntype].w
	ls := otstypes[otssigntype].ls

	if len(otssign) != 4+n*(p+1) {
		return nil, errors.New("lmots: invalid LM-OTS signature")
	}

	C := otssign[4 : 4+n]
	y := otssign[4+n:]

	//Compute Kc as follow
	Q := hash(bytes.Join([][]byte{I, u32str(q), u16str(dMESG), C, message}, []byte("")))
	z := make([]byte, p*n)
	for i := 0; i < p; i++ {
		a := coef(append(Q, u16str(cksm(Q, w, n, ls))...), i, w)
		tmp := make([]byte, n)
		copy(tmp, y[i*n:(i+1)*n])
		for j := a; j < powInt(2, w)-1; j++ {
			tmp = hash(bytes.Join([][]byte{I, u32str(q), u16str(i), u8str(j), tmp}, []byte("")))
		}
		copy(z[i*n:(i+1)*n], tmp)
	}
	Kc := hash(bytes.Join([][]byte{I, u32str(q), u16str(dPBLC), z}, []byte("")))
	return Kc, nil
}
