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

// A LMSPrivateKey represents a LMS private key.
type LMSPrivateKey struct {
	lmstypecode uint   //LMS typecode
	otstypecode uint   //LM-OTS typecode
	I           []byte // a 16-byte identifier for the LMS public/private key pair
	// otspriv     []*OTSPrivateKey //LM-OTS private keys

	seed []byte

	// In the LMS N-time signature scheme, each LM-OTS signature is associated with
	// the leaf of a hash tree, and q is set to the leaf number.
	q int
}

// A LMSPublicKey represents a LMS public key.
type LMSPublicKey struct {
	lmstypecode uint   //LMS typecode
	otstypecode uint   //LM-OTS typecode
	I           []byte // a 16-byte identifier for the LMS public/private key pair
	T1          []byte
}

// GenerateLMSPrivateKey generates a LMS private key.
func GenerateLMSPrivateKey(lmstypecode uint, otstypecode uint) (*LMSPrivateKey, error) {
	if lmstypecode < LMSSHA256M32H5 || lmstypecode > LMSSHA256M32H25 {
		return nil, errors.New("lms: invalid LMS typecode")
	}
	// h := lmstypes[lmstypecode].h
	// m := lmstypes[lmstypecode].m
	lmspriv := new(LMSPrivateKey)
	lmspriv.lmstypecode = lmstypecode
	// lmspriv.otspriv = make([]*OTSPrivateKey, powInt(2, h))

	I := make([]byte, identifierLENGTH)
	_, err := rand.Read(I)
	if err != nil {
		return nil, err
	}

	lmspriv.seed = make([]byte, hashLENGTH)
	_, err = rand.Read(lmspriv.seed)
	if err != nil {
		return nil, err
	}

	// for q := 0; q < powInt(2, h); q++ {
	// 	lmspriv.otspriv[q], err = generateOTSPrivateKey(otstypecode, q, I, seed)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	lmspriv.q = 0
	lmspriv.I = make([]byte, identifierLENGTH)
	copy(lmspriv.I, I)
	lmspriv.otstypecode = otstypecode

	return lmspriv, nil
}

// Public generates the LMS public key.
func (lmspriv *LMSPrivateKey) Public() (*LMSPublicKey, error) {
	err := lmspriv.Validate()
	if err != nil {
		return nil, err
	}

	h := lmstypes[lmspriv.lmstypecode].h
	m := lmstypes[lmspriv.lmstypecode].m
	I := lmspriv.I

	hashstack := make([][]byte, 0)
	num := powInt(2, h) //number of the ots private keys
	for i := 0; i < num; i++ {
		r := i + num
		otspriv, _ := generateOTSPrivateKey(lmspriv.otstypecode, i, lmspriv.I, lmspriv.seed)
		otspub, _ := otspriv.Public()
		tmp := hash(bytes.Join([][]byte{I, u32str(r), u16str(dLEAF), otspub.K}, []byte("")))
		j := i
		for j%2 == 1 {
			r = int((r - 1) / 2)
			j = int((j - 1) / 2)
			leftside := hashstack[len(hashstack)-1]
			hashstack = hashstack[:len(hashstack)-1]
			tmp = hash(bytes.Join([][]byte{I, u32str(r), u16str(dINTR), leftside, tmp}, []byte("")))
		}
		hashstack = append(hashstack, tmp)
	}

	lmspub := new(LMSPublicKey)
	lmspub.lmstypecode = lmspriv.lmstypecode
	lmspub.otstypecode = lmspriv.otstypecode
	lmspub.I = make([]byte, identifierLENGTH)
	copy(lmspub.I, I)
	lmspub.T1 = make([]byte, m)
	copy(lmspub.T1, hashstack[0])

	return lmspub, nil
}

func (lmspriv *LMSPrivateKey) String() string {
	str := string(u32str(int(lmspriv.lmstypecode))) + string(u32str(int(lmspriv.otstypecode))) +
		string(u32str(lmspriv.q)) + string(lmspriv.I) + string(lmspriv.seed)
	str = fmt.Sprintf("%x", str)
	// for i := 0; i < powInt(2, lmstypes[lmspriv.lmstypecode].h); i++ {
	// 	str += lmspriv.otspriv[i].String()
	// }
	return str
}

func (lmspriv *LMSPrivateKey) serialize() []byte {
	return bytes.Join([][]byte{u32str(int(lmspriv.lmstypecode)), u32str(int(lmspriv.otstypecode)),
		u32str(lmspriv.q), lmspriv.I, lmspriv.seed}, []byte(""))
}

func (lmspub *LMSPublicKey) String() string {
	return fmt.Sprintf("%x", string(u32str(int(lmspub.lmstypecode)))+
		string(u32str(int(lmspub.otstypecode)))+string(lmspub.I)+string(lmspub.T1))
}

func (lmspub *LMSPublicKey) serialize() []byte {
	return bytes.Join([][]byte{u32str(int(lmspub.lmstypecode)),
		u32str(int(lmspub.otstypecode)), lmspub.I, lmspub.T1}, []byte(""))
}

// ParseLMSPrivateKey parses a LMS private key in hexadecimal.
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

	lmspriv := new(LMSPrivateKey)
	lmspriv.lmstypecode = lmstypecode
	lmspriv.otstypecode = otstypecode
	lmspriv.q = strTou32(key[8:12])
	lmspriv.I = make([]byte, identifierLENGTH)
	copy(lmspriv.I, key[12:12+identifierLENGTH])
	lmspriv.seed = make([]byte, hashLENGTH)
	copy(lmspriv.seed, key[12+identifierLENGTH:])

	return lmspriv, nil
}

// ParseLMSPublicKey parses a LMS public key in hexadecimal.
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
	lmspub.I = make([]byte, identifierLENGTH)
	copy(lmspub.I, key[8:8+identifierLENGTH])
	lmspub.T1 = make([]byte, len(key)-(8+identifierLENGTH))
	copy(lmspub.T1, key[8+identifierLENGTH:])

	err := lmspub.Validate()
	if err != nil {
		return nil, errors.New("lms: (parse error) invalid LMS public key")
	}

	return lmspub, nil
}

// Sign generates a LMS signature from a LMS private key and a message.
func (lmspriv *LMSPrivateKey) Sign(message []byte) ([]byte, error) {
	err := lmspriv.Validate()
	if err != nil {
		return nil, err
	}

	h := lmstypes[lmspriv.lmstypecode].h
	m := lmstypes[lmspriv.lmstypecode].m
	I := lmspriv.I

	otspriv, _ := generateOTSPrivateKey(lmspriv.otstypecode, lmspriv.q, lmspriv.I, lmspriv.seed)
	otssign, signerr := otspriv.Sign(message)
	if signerr != nil {
		return nil, err
	}

	path := make([]byte, h*m)
	pathnodes := map[int]int{}

	nodenum := lmspriv.q + powInt(2, h)
	for i := 0; i < h; i++ {
		pathnodes[sibing(nodenum)] = i + 1
		nodenum = int(nodenum / 2)
	}

	hashstack := make([][]byte, 0)
	num := powInt(2, h) //number of the ots private keys
	for i := 0; i < num; i++ {
		r := i + num
		otspriv, _ := generateOTSPrivateKey(lmspriv.otstypecode, i, lmspriv.I, lmspriv.seed)
		otspub, _ := otspriv.Public()
		tmp := hash(bytes.Join([][]byte{I, u32str(r), u16str(dLEAF), otspub.K}, []byte("")))
		if pathnodes[r] != 0 {
			copy(path[(pathnodes[r]-1)*m:pathnodes[r]*m], tmp)
		}
		j := i
		for j%2 == 1 {
			r = int((r - 1) / 2)
			j = int((j - 1) / 2)
			leftside := hashstack[len(hashstack)-1]
			hashstack = hashstack[:len(hashstack)-1]
			tmp = hash(bytes.Join([][]byte{I, u32str(r), u16str(dINTR), leftside, tmp}, []byte("")))
			if pathnodes[r] != 0 {
				copy(path[(pathnodes[r]-1)*m:pathnodes[r]*m], tmp)
			}
		}
		hashstack = append(hashstack, tmp[:])
	}

	lmspriv.q++

	return bytes.Join([][]byte{u32str(lmspriv.q - 1), otssign, u32str(int(lmspriv.lmstypecode)), path}, []byte("")), nil
}

// Verify verifies a message with its LMS signature.
func (lmspub *LMSPublicKey) Verify(message, lmssign []byte) error {
	err := lmspub.Validate()
	if err != nil {
		return err
	}

	Tc, tcerr := candidateLMSroot(message, lmssign, lmspub.I, lmspub.lmstypecode, lmspub.otstypecode)
	if tcerr != nil {
		return tcerr
	}

	// fmt.Printf("\n#############\n%x\n\n%x\n#############\n", Tc, lmspub.T1)

	if !bytes.Equal(Tc, lmspub.T1) {
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

	// fmt.Printf("\notssign_lms = %x, otstype = %d, I = %x, q = %d\n", otssign[len(otssign)-10:], otstypecode, I[:10], q)

	Kc, err := otsKeyCandidate(message, otssign, otstypecode, I, q)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("\nKc = %x\n", Kc)

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
		len(lmspriv.seed) != hashLENGTH ||
		// len(lmspriv.otspriv) != powInt(2, lmstypes[lmspriv.lmstypecode].h) ||
		lmspriv.otstypecode > LMOTSSHA256N32W8 || len(lmspriv.I) != identifierLENGTH {
		return errors.New("lms: invalid LMS private key")
	}
	// for i := 0; i < powInt(2, lmstypes[lmspriv.lmstypecode].h); i++ {
	// 	err := lmspriv.otspriv[i].Validate()
	// 	if err != nil || lmspriv.otspriv[i].otstypecode != lmspriv.otstypecode ||
	// 		!bytes.Equal(lmspriv.otspriv[i].I, lmspriv.I) {
	// 		return errors.New("lms: invalid LMS private key")
	// 	}
	// }
	return nil
}

// Validate performs basic sanity checks on the LMS public key.
// It returns nil if the LMS public key is valid, or else an error describing a problem.
func (lmspub *LMSPublicKey) Validate() error {
	if lmspub.lmstypecode < LMSSHA256M32H5 ||
		lmspub.lmstypecode > LMSSHA256M32H25 ||
		lmspub.otstypecode > LMOTSSHA256N32W8 ||
		len(lmspub.I) != identifierLENGTH ||
		len(lmspub.T1) != lmstypes[lmspub.lmstypecode].m {
		return errors.New("lms: invalid LMS public key")
	}
	return nil
}
