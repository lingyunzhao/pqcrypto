// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"bytes"
	"math"
)

type node struct {
	content []byte
	height  int
	idx     int
}

type stack struct {
	nodes   []*node
	height  int
	leafidx int
}

func genMTree(I []byte, skseed []byte, lmstypecode uint, otstypecode uint) *LMSPrivateKey {
	height := lmstypes[lmstypecode].h
	mt := new(LMSPrivateKey)
	mt.height = height
	mt.skseed = make([]byte, hashLENGTH)
	copy(mt.skseed, skseed)
	mt.lmstypecode = lmstypecode
	mt.otstypecode = otstypecode
	mt.q = 0
	mt.id = make([]byte, identifierLENGTH)
	copy(mt.id, I)
	mt.stacks = make([]*stack, height)
	mt.authpath = make([][]byte, height)
	s := new(stack)
	s.nodes = make([]*node, 0)
	s.height = height
	s.leafidx = 0
	for i := 0; i < height; i++ {
		s.update(1, mt.skseed, mt.id, lmstypecode, otstypecode)
		mt.stacks[i] = new(stack)
		mt.stacks[i].height = i
		mt.stacks[i].leafidx = 1 << uint(i)
		mt.stacks[i].nodes = make([]*node, 0)
		mt.stacks[i].push(s.top())
		s.update(1<<uint(i+1)-1, mt.skseed, mt.id, lmstypecode, otstypecode)
		mt.authpath[i] = s.top().content
	}
	s.update(1, mt.skseed, mt.id, lmstypecode, otstypecode)
	mt.root = s.top().content
	return mt
}

func (mt *LMSPrivateKey) refresh() {
	for i := 0; i < mt.height; i++ {
		if ((mt.q+1)/powInt(2, i))*powInt(2, i) == (mt.q + 1) {
			copy(mt.authpath[i], mt.stacks[i].top().content)
			startnode := ((mt.q + 1) + powInt(2, i)) ^ powInt(2, i)
			mt.stacks[i].init(startnode, i)
		}
	}
}

func (mt *LMSPrivateKey) build() {
	for i := 0; i < 2*mt.height-1; i++ {
		min := math.MaxInt32
		focus := 0
		for h := 0; h < mt.height; h++ {
			low := mt.stacks[h].low()
			if low < min {
				min = low
				focus = h
			}
		}
		mt.stacks[focus].update(1, mt.skseed, mt.id, mt.lmstypecode, mt.otstypecode)
	}
}

func (mt *LMSPrivateKey) traversal() {
	mt.refresh()
	mt.build()
	mt.q++
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

func (s *stack) update(n int, skseed []byte, I []byte, lmstypecode uint, otstypecode uint) {
	if len(s.nodes) > 0 && s.top().height == s.height {
		return
	}
	h := lmstypes[lmstypecode].h
	for i := 0; i < n; i++ {
		if len(s.nodes) >= 2 && s.nexttop().height == s.top().height {
			right := s.pop()
			left := s.pop()
			nd := new(node)
			nd.idx = right.idx >> 1
			nd.height = right.height + 1
			nd.content = hash(bytes.Join([][]byte{I, u32str(powInt(2, h-nd.height) + nd.idx), u16str(dINTR), left.content, right.content}, []byte("")))
			s.push(nd)
			continue
		}
		otspriv, _ := generateOTSPrivateKey(otstypecode, s.leafidx, I, skseed)
		otspub, _ := otspriv.Public()
		lnd := new(node)
		lnd.content = hash(bytes.Join([][]byte{I, u32str(powInt(2, h) + s.leafidx), u16str(dLEAF), otspub.K}, []byte("")))
		lnd.idx = s.leafidx
		lnd.height = 0
		s.push(lnd)
		s.leafidx++
	}
}
