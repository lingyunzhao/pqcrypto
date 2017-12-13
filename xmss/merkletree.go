// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"bytes"
	"math"
	// "fmt"
)

type node struct {
	content []byte
	height  int
	idx     int
}

func (nd *node) serialize() []byte {
	return bytes.Join([][]byte{toByte(uint64(nd.height), 4), toByte(uint64(nd.idx), 4), nd.content}, []byte(""))
}

func parsenode(ndbytes []byte) *node {
	nd := new(node)
	nd.height = strToInt(ndbytes[:4])
	nd.idx = strToInt(ndbytes[4:8])
	nd.content = make([]byte, len(ndbytes[8:]))
	copy(nd.content, ndbytes[8:])
	return nd
}

type stack struct {
	nodes   []*node
	height  int
	leafidx int
}

func (s *stack) serialize() []byte {
	nds := []byte{}
	for i := 0; i < len(s.nodes); i++ {
		nds = append(nds, s.nodes[i].serialize()...)
	}
	return bytes.Join([][]byte{toByte(uint64(len(s.nodes)), 4), toByte(uint64(s.height), 4), toByte(uint64(s.leafidx), 4), nds}, []byte(""))
}

func parsestack(sbytes []byte, n int) *stack {
	ndlen := strToInt(sbytes[:4])
	s := new(stack)
	s.nodes = make([]*node, ndlen)
	s.height = strToInt(sbytes[4:8])
	s.leafidx = strToInt(sbytes[8:12])
	n += 8
	if n*ndlen != len(sbytes[12:]) {
		return nil
	}
	for i := 0; i < ndlen; i++ {
		s.nodes[i] = parsenode(sbytes[12+n*i : 12+n*(i+1)])
	}
	return s
}

type merkle struct {
	height   int
	idx      int
	hsty     int
	layer    int
	idxtree  int
	wotspty  uint
	root     []byte
	skseed   []byte
	seed     []byte
	authpath [][]byte
	stacks   []*stack
}

func (mt *merkle) reducedSK() []byte {
	ss := make([]byte, 0)
	for i := 0; i < len(mt.stacks); i++ {
		tmps := mt.stacks[i].serialize()
		// fmt.Println(len(tmps))
		ss = append(ss, toByte(uint64(len(tmps)), 4)...)
		ss = append(ss, tmps...)
	}
	return bytes.Join([][]byte{toByte(uint64(mt.idx), 4) /*toByte(uint64(mt.layer), 4),*/, toByte(uint64(mt.idxtree), 4),
		mt.root, twoDto1D(mt.authpath), ss /*, mt.skseed, mt.seed*/}, []byte(""))
}

func (mt *merkle) serialize() []byte {
	ss := make([]byte, 0)
	for i := 0; i < len(mt.stacks); i++ {
		tmps := mt.stacks[i].serialize()
		// fmt.Println(len(tmps))
		ss = append(ss, toByte(uint64(len(tmps)), 4)...)
		ss = append(ss, tmps...)
	}
	return bytes.Join([][]byte{toByte(uint64(mt.idx), 4), toByte(uint64(mt.layer), 4), toByte(uint64(mt.idxtree), 4),
		mt.root, twoDto1D(mt.authpath), ss, mt.skseed, mt.seed}, []byte(""))
}

func parseReducedSK(mtbytes []byte, layer int, skseed []byte, seed []byte, skprf []byte, xmssty uint) *SK {
	wotspty := xmsstowotsp(xmssty)
	n := xmsstypes[xmssty].n
	h := xmsstypes[xmssty].h
	hsty := xmsstypes[xmssty].hsty
	if len(mtbytes) < 4+4+4+n+n*h {
		// fmt.Println("Here!", len(mtbytes))
		return nil
	}
	// fmt.Println("len(mtbytes) =", len(mtbytes))
	// fmt.Println("true len =", 12+n+n*h+560+n+n)
	mt := new(merkle)
	mt.idx = strToInt(mtbytes[:4])
	mtbytes = mtbytes[4:]
	mt.layer = layer
	mt.idxtree = strToInt(mtbytes[:4])
	mtbytes = mtbytes[4:]
	mt.root = make([]byte, n)
	copy(mt.root, mtbytes[:n])
	mtbytes = mtbytes[n:]
	mt.authpath = oneDto2D(mtbytes[:n*h], h, n)
	mtbytes = mtbytes[n*h:]

	mt.stacks = make([]*stack, h)
	for i := 0; i < h; i++ {
		if len(mtbytes) < 4 {
			return nil
		}
		slen := strToInt(mtbytes[:4])
		mtbytes = mtbytes[4:]
		if len(mtbytes) < slen {
			// fmt.Println(i, len(mtbytes), slen)
			return nil
		}
		mt.stacks[i] = parsestack(mtbytes[:slen], n)
		if mt.stacks[i] == nil {
			// fmt.Println("Here!!!")
			return nil
		}
		mtbytes = mtbytes[slen:]
	}
	// if len(mtbytes) != 2*n {
	// 	return nil
	// }
	mt.skseed = make([]byte, n)
	copy(mt.skseed, skseed)
	mt.seed = make([]byte, n)
	copy(mt.seed, seed)

	mt.hsty = hsty
	mt.wotspty = wotspty
	mt.height = h

	xsk := new(SK)
	xsk.oid = xmssty
	xsk.skprf = make([]byte, n)
	copy(xsk.skprf, skprf)
	xsk.mt = mt
	return xsk
}

func parsemerkle(mtbytes []byte, n int, h int, hsty int, wotspty uint) *merkle {
	if len(mtbytes) < 4+4+4+n+n*h {
		// fmt.Println(len(mtbytes))
		return nil
	}
	// fmt.Println("len(mtbytes) =", len(mtbytes))
	// fmt.Println("true len =", 12+n+n*h+560+n+n)
	mt := new(merkle)
	mt.idx = strToInt(mtbytes[:4])
	mtbytes = mtbytes[4:]
	mt.layer = strToInt(mtbytes[:4])
	mtbytes = mtbytes[4:]
	mt.idxtree = strToInt(mtbytes[:4])
	mtbytes = mtbytes[4:]
	mt.root = make([]byte, n)
	copy(mt.root, mtbytes[:n])
	mtbytes = mtbytes[n:]
	mt.authpath = oneDto2D(mtbytes[:n*h], h, n)
	mtbytes = mtbytes[n*h:]

	mt.stacks = make([]*stack, h)
	for i := 0; i < h; i++ {
		if len(mtbytes) < 4 {
			return nil
		}
		slen := strToInt(mtbytes[:4])
		mtbytes = mtbytes[4:]
		if len(mtbytes) < slen {
			// fmt.Println(i, len(mtbytes), slen)
			return nil
		}
		mt.stacks[i] = parsestack(mtbytes[:slen], n)
		if mt.stacks[i] == nil {
			return nil
		}
		mtbytes = mtbytes[slen:]
	}
	if len(mtbytes) != 2*n {
		return nil
	}
	mt.skseed = make([]byte, n)
	copy(mt.skseed, mtbytes[:n])
	mtbytes = mtbytes[n:]
	mt.seed = make([]byte, n)
	copy(mt.seed, mtbytes[:n])

	mt.hsty = hsty
	mt.wotspty = wotspty
	mt.height = h
	return mt
}

func genMTree(height int, skseed []byte, seed []byte, hsty int, wotspty uint, layer int, idxtree int) *merkle {
	mt := new(merkle)
	mt.height = height
	mt.skseed = make([]byte, len(skseed))
	copy(mt.skseed, skseed)
	mt.seed = make([]byte, len(seed))
	copy(mt.seed, seed)
	mt.hsty = hsty
	mt.wotspty = wotspty
	mt.idx = 0
	mt.layer = layer
	mt.idxtree = idxtree
	mt.stacks = make([]*stack, height)
	mt.authpath = make([][]byte, height)
	s := new(stack)
	s.nodes = make([]*node, 0)
	s.height = height
	s.leafidx = 0
	for i := 0; i < height; i++ {
		s.update(1, skseed, seed, hsty, wotspty, layer, idxtree)
		// if i == 0 {
		//         fmt.Printf("gen = %x\n", s.top().content)
		// }
		mt.stacks[i] = new(stack)
		mt.stacks[i].height = i
		mt.stacks[i].leafidx = 1 << uint(i)
		mt.stacks[i].nodes = make([]*node, 0)
		// if i == 0 {
		//         fmt.Printf("gen pub[0] %x\n", s.top().content)
		// }
		mt.stacks[i].push(s.top())
		s.update(1<<uint(i+1)-1, skseed, seed, hsty, wotspty, layer, idxtree)
		// if i>0 {
		// mt.stacks[i].push(s.top())
		// }
		mt.authpath[i] = s.top().content
		// if i == 0 {
		//         fmt.Printf("gen pub[1] %x\n", mt.authpath[i])
		// }
	}
	s.update(1, skseed, seed, hsty, wotspty, layer, idxtree)
	mt.root = s.top().content
	return mt
}

func (mt *merkle) refresh() {
	for i := 0; i < mt.height; i++ {
		if ((mt.idx+1)/pow2(i))*pow2(i) == (mt.idx + 1) {
			// fmt.Printf("h = %d\n",i)
			copy(mt.authpath[i], mt.stacks[i].top().content)
			// fmt.Printf("i = %d, ref = %x\n", i, mt.authpath[i])
			startnode := ((mt.idx + 1) + pow2(i)) ^ pow2(i)
			mt.stacks[i].init(startnode, i)
			// fmt.Println("strnd = ", startnode, "idx =", mt.idx, "pow2(i) =", pow2(i))
		}
	}
}

func (mt *merkle) build() {
	for i := 0; i < 2*mt.height-1; i++ {
		min := math.MaxInt32
		focus := 0
		for h := 0; h < mt.height; h++ {
			low := mt.stacks[h].low()
			// fmt.Println("low =",low)
			if low < min {
				min = low
				focus = h
			}
		}
		// fmt.Println(focus)
		mt.stacks[focus].update(1, mt.skseed, mt.seed, mt.hsty, mt.wotspty, mt.layer, mt.idxtree)
	}
}

func (mt *merkle) traversal() {
	// fmt.Printf("idx = %d", mt.idx)
	// for i := 0; i < len(mt.stacks); i++ {
	// 	fmt.Printf(" %d", len(mt.stacks[i].nodes))
	// }
	// fmt.Println()
	mt.refresh()
	mt.build()
	mt.idx++
}

func (s *stack) init(startnode int, height int) {
	s.leafidx = startnode
	s.height = height
	s.nodes = s.nodes[:0]
}

func (s *stack) push(nd *node) {
	s.nodes = append(s.nodes, nd)
}

func (s *stack) pop() *node {
	nd := s.nodes[len(s.nodes)-1]
	s.nodes = s.nodes[:len(s.nodes)-1]
	return nd
}

func (s *stack) top() *node {
	return s.nodes[len(s.nodes)-1]
}

func (s *stack) nexttop() *node {
	return s.nodes[len(s.nodes)-2]
}

func (s *stack) low() int {
	if len(s.nodes) == 0 {
		return s.height
	}
	if s.top().height == s.height {
		return math.MaxInt32
	}
	min := math.MaxInt32
	for i := 0; i < len(s.nodes); i++ {
		if s.nodes[i].height < min {
			min = s.nodes[i].height
		}
	}
	return min
}

func (s *stack) update(n int, skseed []byte, seed []byte, hsty int, wotspty uint, layer int, idxtree int) {
	if len(s.nodes) > 0 && s.top().height == s.height {
		return
	}

	adrs := toByte(0, addrlen)
	set(adrs, HASHTREE, addrtype)
	set(adrs, int64(layer), layeraddr)
	set(adrs, int64(idxtree), treeaddr)
	for i := 0; i < n; i++ {
		if len(s.nodes) >= 2 && s.nexttop().height == s.top().height {
			right := s.pop()
			left := s.pop()
			nd := new(node)
			nd.idx = right.idx >> 1
			nd.height = right.height + 1
			set(adrs, int64(right.height), treeheight)
			set(adrs, int64(nd.idx), treeindex)
			// if s.leafidx == 2 {
			// 	fmt.Printf("uadrs = %x\n", adrs)
			// }
			nd.content = randhash(left.content, right.content, seed, adrs, hsty)
			// if s.leafidx == 2 {
			// 	fmt.Printf("u_nd = %x\n", nd.content)
			// }
			s.push(nd)
			continue
		}
		wadrs := toByte(0, addrlen)
		set(wadrs, OTS, addrtype)
		set(wadrs, int64(s.leafidx), otsaddr)
		set(wadrs, int64(layer), layeraddr)
		set(wadrs, int64(idxtree), treeaddr)
		// if s.leafidx == 0 {
		// 	fmt.Printf("wots1[0] adrs = %x\nwots1[0] sked = %x\nwotsp[0] getseed = %x\n", wadrs, skseed, getseed(skseed, adrs, hsty))
		// }
		// fmt.Println("add leaf", s.leafidx)
		wsk, _ := wotspGenSK(getseed(skseed, wadrs, hsty), wotspty)
		// if s.leafidx == 0 {
		// 	// fmt.Printf("hsty = %d, wotspty = %x\nwots2[0]   sk = %x\nwots2[0] adrs = %x\nwots2[0] seed = %x\n", hsty, wotspty, wsk.sk[0], wadrs, seed)
		// 	fmt.Printf("hsty = %d, wotspty = %x\nwots2[0]   sk = %x\n", hsty, wotspty, wsk.sk[0])
		// }
		wpk := wsk.wotspGenPK(wadrs, seed)
		set(wadrs, LTREE, addrtype)
		set(wadrs, int64(s.leafidx), ltreeaddr)
		// if s.leafidx == 0 {
		// 	fmt.Printf("wots3[0] adrs = %x\nwots3[0]   pk = %x\n", wadrs, wpk.pk[0])
		// }
		ndcontent := wpk.ltree(wadrs)
		// if s.leafidx == 0 || s.leafidx == 1 {
		// 	fmt.Printf("tpub[%d] = %x\n", s.leafidx, ndcontent)
		// }
		lnd := new(node)
		lnd.content = ndcontent
		lnd.idx = s.leafidx
		lnd.height = 0
		s.push(lnd)
		s.leafidx++
	}
}
