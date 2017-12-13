// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// A SK represents an XMSS private key.
type SK struct {
	oid   uint
	skprf []byte
	mt    *merkle
}

func (xsk *SK) String() string {
	// fmt.Println("len(skprf) =", len(xsk.skprf))
	// fmt.Println("string:", len(xsk.mt.serialize()), len(xsk.serialize()))
	return fmt.Sprintf("%x", xsk.serialize())
}

func (xsk *SK) serialize() []byte {
	return bytes.Join([][]byte{toByte(uint64(xsk.oid), 4), xsk.skprf, xsk.mt.serialize()}, []byte(""))
}

// ParseSK parses a XMSS private key in hexadecimal.
func ParseSK(sk string) (*SK, error) {
	skbytes, err := hex.DecodeString(sk)
	if err != nil {
		return nil, err
	}
	// fmt.Println("len(skbytes) =", len(skbytes))
	// fmt.Println("true len =", 988+4+32)
	if len(skbytes) < 4 {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	xsk := new(SK)
	oid := strToUint(skbytes[:4])
	skbytes = skbytes[4:]
	if xmsstypes[oid] == nil {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	n := xmsstypes[oid].n
	if len(skbytes) < n {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	xsk.skprf = make([]byte, n)
	copy(xsk.skprf, skbytes[:n])
	skbytes = skbytes[n:]
	wotspty := xmsstowotsp(oid)
	hsty := xmsstypes[oid].hsty
	h := xmsstypes[oid].h
	xsk.mt = parsemerkle(skbytes, n, h, hsty, wotspty)
	if xsk.mt == nil {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	xsk.oid = oid
	return xsk, nil
}

// A PK represents an XMSS public key.
type PK struct {
	oid uint
	// layer   int
	// idxtree int
	root []byte
	seed []byte
}

func (xpk *PK) serialize() []byte {
	return bytes.Join([][]byte{toByte(uint64(xpk.oid), 4), xpk.root, xpk.seed}, []byte(""))
}

func (xpk *PK) String() string {
	return fmt.Sprintf("%x", xpk.serialize())
}

// ParsePK parses a XMSS public key in hexadecimal.
func ParsePK(pk string) (*PK, error) {
	pkbytes, err := hex.DecodeString(pk)
	if err != nil {
		return nil, err
	}

	if len(pkbytes) < 4 {
		return nil, errors.New("xmss: invalid XMSS public key")
	}

	oid := strToUint(pkbytes[:4])
	if xmsstypes[oid] == nil {
		return nil, errors.New("xmss: invalid XMSS public key")
	}
	n := xmsstypes[oid].n

	if len(pkbytes) != 4+n+n {
		return nil, errors.New("xmss: invalid XMSS public key")
	}

	xpk := new(PK)
	xpk.oid = oid
	xpk.root = make([]byte, n)
	copy(xpk.root, pkbytes[4:4+n])
	xpk.seed = make([]byte, n)
	copy(xpk.seed, pkbytes[4+n:4+n+n])

	return xpk, nil
}

// // XMSSkeyGen generates an XMSS key pair
// func XMSSkeyGen(oid uint) (*SK, *PK, error) {
// 	if oid < XMSSSHA2H10W256 || oid > XMSSSHAKE20W512 {
// 		return nil, nil, errors.New("xmss: invalid XMSS oid")
// 	}
// 	xsk := new(SK)
// 	xsk.oid = oid
// 	h := xmsstypes[oid].h
// 	n := xmsstypes[oid].n
// 	hsty := xmsstypes[oid].hsty
// 	// wotspty := xmsstowotsp(oid)
// 	seed := make([]byte, n)
// 	_, err := rand.Read(seed)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	xsk.skprf = make([]byte, n)
// 	_, err = rand.Read(xsk.skprf)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	xsk.mt = genMTree(h, seed, hsty, xmsstowotsp(oid))
//
// 	// adrs := toByte(0, 32)
// 	// root := xsk.treehash(0, h, adrs)
// 	// xsk.root = make([]byte, len(root))
// 	// copy(xsk.root, root)
//
// 	xpk := new(PK)
// 	xpk.oid = oid
// 	xpk.seed = make([]byte, n)
// 	xpk.root = make([]byte, len(xsk.mt.root))
// 	copy(xpk.root, xsk.mt.root)
// 	copy(xpk.seed, seed)
//
// 	return xsk, xpk, nil
// }

// KeyGen generates an XMSS key pair
func KeyGen(oid uint) (*SK, *PK, error) {
	// if oid < XMSSSHA2H10W256 || oid > XMSSSHAKEH20W512 {
	// 	return nil, nil, errors.New("xmss: invalid XMSS oid")
	// }
	if xmsstypes[oid] == nil {
		return nil, nil, errors.New("xmss: invalid XMSS oid")
	}
	n := xmsstypes[oid].n
	seed := make([]byte, n)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, nil, err
	}
	skseed := make([]byte, n)
	_, err = rand.Read(skseed)
	if err != nil {
		return nil, nil, err
	}
	skprf := make([]byte, n)
	_, err = rand.Read(skprf)
	if err != nil {
		return nil, nil, err
	}
	return xmsskeyGen(oid, skseed, seed, skprf, 0, 0)
}

// Public generates the public key of a private key.
func (xsk *SK) Public() *PK {
	xpk := new(PK)
	xpk.oid = xsk.oid
	xpk.root = make([]byte, len(xsk.mt.root))
	copy(xpk.root, xsk.mt.root)
	xpk.seed = make([]byte, len(xsk.mt.seed))
	copy(xpk.seed, xsk.mt.seed)
	return xpk
}

func xmsskeyGen(oid uint, skseed []byte, seed []byte, skprf []byte, layer int, idxtree int) (*SK, *PK, error) {
	// if oid < XMSSSHA2H10W256 || oid > XMSSSHAKE20W512 {
	// 	return nil, nil, errors.New("xmss: invalid XMSS oid")
	// }
	xsk := new(SK)
	xsk.oid = oid
	h := xmsstypes[oid].h
	n := xmsstypes[oid].n
	hsty := xmsstypes[oid].hsty
	// wotspty := xmsstowotsp(oid)
	// seed := make([]byte, n)
	// _, err := rand.Read(seed)
	// if err != nil {
	// 	return nil, nil, err
	// }
	xsk.skprf = make([]byte, n)
	copy(xsk.skprf, skprf)
	// _, err := rand.Read(xsk.skprf)
	// if err != nil {
	// 	return nil, nil, err
	// }
	xsk.mt = genMTree(h, skseed, seed, hsty, xmsstowotsp(oid), layer, idxtree)

	// adrs := toByte(0, 32)
	// root := xsk.treehash(0, h, adrs)
	// xsk.root = make([]byte, len(root))
	// copy(xsk.root, root)

	xpk := new(PK)
	xpk.oid = oid
	xpk.seed = make([]byte, n)
	xpk.root = make([]byte, len(xsk.mt.root))
	// xpk.layer = layer
	// xpk.idxtree = idxtree
	copy(xpk.root, xsk.mt.root)
	copy(xpk.seed, seed)

	return xsk, xpk, nil
}

// Sign generates an XMSS signature and update the XMSS private key.
func (xsk *SK) Sign(message []byte) ([]byte, error) {
	if xmsstypes[xsk.oid] == nil {
		return nil, errors.New("xmss: invalid XMSS private key")
	}
	h := xmsstypes[xsk.oid].h
	if xsk.mt.idx >= pow2(h) {
		return nil, errors.New("xmss: attempted overuse of XMSS private key")
	}
	hsty := xsk.mt.hsty
	n := xmsstypes[xsk.oid].n
	r := fn(toByte(uint64(xsk.mt.idx), 32), xsk.skprf, hsty, prf)
	// fmt.Printf("s: idx=%d, r = %x\n", xsk.mt.idx, r)
	m := fn(message, bytes.Join([][]byte{r, xsk.mt.root, toByte(uint64(xsk.mt.idx), n)}, []byte("")), hsty, hmsg)
	adrs := toByte(0, addrlen)
	xsig := bytes.Join([][]byte{toByte(uint64(xsk.mt.idx), 4), r}, []byte(""))
	set(adrs, int64(xsk.mt.layer), layeraddr)
	set(adrs, int64(xsk.mt.idxtree), treeaddr)
	xsig = append(xsig, twoDto1D(xsk.treeSig(m, adrs))...)
	// tsig := xsk.treeSig(m, adrs)
	// for i := 0; i < len(tsig); i++ {
	// 	xsig = append(xsig, tsig[i]...)
	// }
	return xsig, nil
}

// Verify an XMSS signature using the corresponding XMSS public key and a message.
// func (xpk *PK) Verify(message, xsig []byte) bool {
// 	adrs := toByte(0, 32)
// 	set(adrs, int64(xpk.layer), layeraddr)
// 	set(adrs, int64(xpk.idxtree), treeaddr)
// 	return xpk.verify(message, xsig, adrs)
// adrs := toByte(0, addrlen)
// hsty := xmsstypes[xpk.oid].hsty
// n := xmsstypes[xpk.oid].n
// l := xmsstypes[xpk.oid].l
// h := xmsstypes[xpk.oid].h
// if len(xsig) != 4+n+l*n+n*h {
// 	return false
// }
// idx := strToInt(xsig[:4])
// r := xsig[4 : 4+n]
// // fmt.Printf("v: idx=%d, r = %x\n", idx, r)
// wsig := make([][]byte, l)
// for i := 0; i < l; i++ {
// 	wsig[i] = xsig[4+n+n*i : 4+n+n*(i+1)]
// }
// authpath := make([][]byte, h)
// for i := 0; i < h; i++ {
// 	authpath[i] = xsig[4+n+l*n+n*i : 4+n+l*n+n*(i+1)]
// }
// m := fn(message, bytes.Join([][]byte{r, xpk.root, toByte(idx, n)}, []byte("")), hsty, hmsg)
// root := rootFromSig(m, xpk.seed, wsig, authpath, adrs, idx, xmsstowotsp(xpk.oid), h)
// // fmt.Printf("s: len(root) = %d, root = %x\nv: len(root)= %d, root = %x\n",
// // 	len(xpk.root), xpk.root, len(root), root)
// if !bytes.Equal(root, xpk.root) {
// 	// fmt.Printf("s: len(root) = %d, root = %x\nv: len(root)= %d, root = %x\n",
// 	// 	len(xpk.root), xpk.root, len(root), root)
// 	return false
// }
// return true
// }

// Verify an XMSS signature using the corresponding XMSS public key and a message.
func (xpk *PK) Verify(message []byte, xsig []byte) bool {
	adrs := toByte(0, 32)
	// set(adrs, int64(xpk.layer), layeraddr)
	// set(adrs, int64(xpk.idxtree), treeaddr)
	set(adrs, 0, layeraddr)
	set(adrs, 0, treeaddr)
	hsty := xmsstypes[xpk.oid].hsty
	n := xmsstypes[xpk.oid].n
	l := xmsstypes[xpk.oid].l
	h := xmsstypes[xpk.oid].h
	if len(xsig) != 4+n+l*n+n*h {
		return false
	}
	idx := strToInt(xsig[:4])
	r := xsig[4 : 4+n]
	// fmt.Printf("v: idx=%d, r = %x\n", idx, r)
	// wsig := make([][]byte, l)
	// for i := 0; i < l; i++ {
	// 	wsig[i] = xsig[4+n+n*i : 4+n+n*(i+1)]
	// }
	wsig := oneDto2D(xsig[4+n:4+n+n*l], l, n)
	// authpath := make([][]byte, h)
	// for i := 0; i < h; i++ {
	// 	authpath[i] = xsig[4+n+l*n+n*i : 4+n+l*n+n*(i+1)]
	// }
	authpath := oneDto2D(xsig[4+n+n*l:4+n+n*l+n*h], h, n)
	m := fn(message, bytes.Join([][]byte{r, xpk.root, toByte(uint64(idx), n)}, []byte("")), hsty, hmsg)
	root := rootFromSig(m, xpk.seed, wsig, authpath, adrs, idx, xmsstowotsp(xpk.oid), h)
	// fmt.Printf("s: len(root) = %d, root = %x\nv: len(root)= %d, root = %x\n",
	// 	len(xpk.root), xpk.root, len(root), root)
	if !bytes.Equal(root, xpk.root) {
		// fmt.Printf("s: len(root) = %d, root = %x\nv: len(root)= %d, root = %x\n",
		// 	len(xpk.root), xpk.root, len(root), root)
		return false
	}
	return true
}

func (xsk *SK) treeSig(m []byte, adrs address) [][]byte {
	set(adrs, OTS, addrtype)
	set(adrs, int64(xsk.mt.idx), otsaddr)
	// fmt.Printf("treeSig1 adrs = %x\ntreeSig1 sked = %x\nhsty = %d, wotspty = %x\n", adrs, xsk.mt.skseed, xsk.mt.hsty, xsk.oid)
	// fmt.Printf("treeSign getseed = %x\n", getseed(xsk.mt.skseed, adrs, xsk.mt.hsty))
	wsk, _ := wotspGenSK(getseed(xsk.mt.skseed, adrs, xsk.mt.hsty), xmsstowotsp(xsk.oid))
	// wsig := wsk.sign(m, adrs, xsk.mt.seed)
	// fmt.Printf("treeSign   sk = %x\n", wsk.sk[0])
	// fmt.Printf("treeSig2 adrs = %x\ntreeSig2 seed = %x\n", adrs, xsk.mt.seed)
	sig := wsk.sign(m, adrs, xsk.mt.seed)
	// fmt.Printf("tsig: %x\n", sig[0])
	wsklen := len(sig)
	sig = append(sig, make([][]byte, len(xsk.mt.authpath))...)
	for i := 0; i < len(xsk.mt.authpath); i++ {
		sig[wsklen+i] = make([]byte, len(xsk.mt.authpath[i]))
		copy(sig[wsklen+i], xsk.mt.authpath[i])
	}
	// authpath := make([][]byte, len(xsk.mt.authpath))
	// copy(authpath, xsk.mt.authpath)
	// sig := append(wsig, xsk.mt.authpath...)
	// sig := append(wsig, authpath...)
	// fmt.Printf("bsigpub[1] %x\n", sig[67])
	if xsk.mt.idx == pow2(xmsstypes[xsk.oid].h)-1 {
		xsk.mt.idx++
	} else {
		xsk.mt.traversal()
	}
	// fmt.Printf("asigpub[1] %x\n", sig[67])
	return sig
}

func rootFromSig(m []byte, seed []byte, wsig [][]byte, authpath [][]byte, adrs address, idx int, wotspty uint, h int) []byte {
	set(adrs, OTS, addrtype)
	set(adrs, int64(idx), otsaddr)
	wpk := new(wotsppk)
	// fmt.Printf("wsig: %x\n", wsig[0])
	// fmt.Printf("rootFSi1 adrs = %x\nrootFSi1 seed = %x\n", adrs, seed)
	wpk.pk = sigortmppk(m, adrs, seed, wsig, wotspty, computewotsptmppk)
	// fmt.Printf("tmpwpk = %x\n", wpk.pk[0])
	wpk.wotspty = wotspty
	wpk.seed = seed
	// fmt.Printf("rootFSig   pk = %x\n", wpk.pk[0])
	set(adrs, LTREE, addrtype)
	set(adrs, int64(idx), ltreeaddr)
	// fmt.Printf("rootFSig adrs = %x\n", adrs)
	// fmt.Printf("rootFSi2 adrs = %x\n", adrs)
	nd := wpk.ltree(adrs)
	// fmt.Printf("ver pub[%d] %x\nver sib[%d] %x\n", idx, nd, idx, authpath[0])
	set(adrs, HASHTREE, addrtype)
	set(adrs, int64(idx), treeindex)
	// set(adrs, 0, ltreeaddr)
	// fmt.Println(idx, int64(idx))
	hsty := wotsptypes[wotspty].hsty
	for k := 0; k < h; k++ {
		// if k == 0 && idx == 1 {
		// 	fmt.Printf("adrs1 = %x\n", adrs)
		// }
		set(adrs, int64(k), treeheight)
		// if k == 0 && idx == 1 {
		// 	fmt.Printf("adrs2 = %x\n", adrs)
		// }
		if floor(float64(idx)/float64(pow2(k)))%2 == 0 {
			set(adrs, get(adrs, treeindex)/2, treeindex)
			// if k == 0 {
			// 	fmt.Printf("H = 1, idx = %d\n%x\n%x\n%x\n%x\n", idx, nd, authpath[k], seed, adrs)
			// }
			nd = randhash(nd, authpath[k], seed, adrs, hsty)
		} else {
			// fmt.Println(get(adrs, treeindex))
			// if k == 0 && idx == 1 {
			// 	fmt.Printf("adrs3 = %x, tridx= %d\n", adrs, get(adrs, treeindex))
			// }
			set(adrs, (get(adrs, treeindex)-1)/2, treeindex)
			// if k == 0 && idx == 1 {
			// 	fmt.Printf("adrs4 = %x, tridx= %d\n", adrs, get(adrs, treeindex))
			// }
			// fmt.Println(get(adrs, treeindex))
			// if k == 0 {
			// 	fmt.Printf("H = 1, idx = %d\n%x\n%x\n%x\n%x\n", idx, nd, authpath[k], seed, adrs)
			// }
			// if k == 0 {
			// 	fmt.Printf("adrs = %x\n", adrs)
			// }
			nd = randhash(authpath[k], nd, seed, adrs, hsty)
			// if k == 0 {
			// 	fmt.Printf("nd = %x\n", nd)
			// }
		}
		// if k == 0 {
		// 	fmt.Printf("H = 1 %x\n", nd)
		// }
	}
	return nd
}

// // XMSSkeyGen generates an XMSS key pair
// func XMSSkeyGen(oid uint) (*SK, *PK, error) {
// 	if oid < XMSSSHA2H10W256 || oid > XMSSSHAKE20W512 {
// 		return nil, nil, errors.New("xmss: invalid XMSS oid")
// 	}
// 	xsk := new(SK)
// 	xsk.oid = oid
// 	xsk.idx = 0
// 	// h := xmsstypes[oid].h
// 	n := xmsstypes[oid].n
// 	// wotspty := xmsstowotsp(oid)
// 	xsk.seed = make([]byte, n)
// 	_, err := rand.Read(xsk.seed)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	xsk.skprf = make([]byte, n)
// 	_, err = rand.Read(xsk.skprf)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	adrs := toByte(0, 32)
// 	root := xsk.treehash(0, h, adrs)
// 	xsk.root = make([]byte, len(root))
// 	copy(xsk.root, root)
//
// 	xpk := new(PK)
// 	xpk.oid = oid
// 	xpk.seed = make([]byte, n)
// 	xpk.root = make([]byte, len(root))
// 	copy(xpk.root, root)
// 	copy(xpk.seed, xsk.seed)
//
// 	return xsk, xpk, nil
// }

// func (xsk *SK) treehash(s int, t int, adrs address) []byte {
// 	if s%(1<<uint(t)) != 0 {
// 		return nil
// 	}
// 	seed := xsk.seed
// 	wotspty := xmsstowotsp(xsk.oid)
// 	hsty := xmsstypes[xsk.oid].hsty
// 	hashstack := make([][]byte, 0)
// 	for i := 0; i < pow2(t); i++ {
// 		wsk, _ := wotspGenSK(fn(toByte(i, 32), seed, hsty, prf), wotspty)
// 		set(adrs, 0, addrtype)
// 		set(adrs, int64(s+i), otsaddr)
// 		wpk := wsk.wotspGenPK(adrs, seed)
// 		set(adrs, 1, addrtype)
// 		set(adrs, int64(s+i), treeaddr)
// 		nd := wpk.ltree(adrs)
// 		set(adrs, 2, addrtype)
// 		set(adrs, 0, treeheight)
// 		set(adrs, int64(s+i), treeindex)
// 		j := i
// 		for j%2 == 1 {
// 			j = int((j - 1) / 2)
// 			leftside := hashstack[len(hashstack)-1]
// 			hashstack = hashstack[:len(hashstack)-1]
// 			set(adrs, (get(adrs, treeindex)-1)/2, treeindex)
// 			nd = randhash(leftside, nd, seed, adrs, hsty)
// 			set(adrs, get(adrs, treeheight)+1, treeheight)
// 		}
// 		hashstack = append(hashstack, nd)
// 	}
// 	return hashstack[0]
// }

func randhash(left []byte, right []byte, seed []byte, adrs address, hsty int) []byte {
	set(adrs, 0, keyAndMask)
	key := fn(adrs, seed, hsty, prf)
	set(adrs, 1, keyAndMask)
	bm0 := fn(adrs, seed, hsty, prf)
	set(adrs, 2, keyAndMask)
	bm1 := fn(adrs, seed, hsty, prf)
	set(adrs, 0, keyAndMask)

	return fn(append(xor(left, bm0), xor(right, bm1)...), key, hsty, h)
}

func (wpk *wotsppk) ltree(adrs address) []byte {
	l := wotsptypes[wpk.wotspty].l
	hsty := wotsptypes[wpk.wotspty].hsty
	set(adrs, 0, treeheight)
	for l > 1 {
		for i := 0; i < floor(float64(l)/2); i++ {
			set(adrs, int64(i), treeindex)
			wpk.pk[i] = randhash(wpk.pk[2*i], wpk.pk[2*i+1], wpk.seed, adrs, hsty)
		}
		if l&0x01 == 1 {
			copy(wpk.pk[floor(float64(l)/2)], wpk.pk[l-1])
		}
		l = ceil(float64(l) / 2)
		set(adrs, get(adrs, treeheight)+1, treeheight)
	}
	set(adrs, 0, treeheight)
	set(adrs, 0, treeindex)
	set(adrs, 0, ltreeaddr)
	return wpk.pk[0]
}
