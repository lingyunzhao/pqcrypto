// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldwm

import (
	"fmt"
)

func Example() {
	// test message
	message := []byte("Hello, world!")

	// *************************************** LM-OTS ***************************************

	// generates a LM-OTS private key with the type LMOTSSHA256N32W1
	lmotspriv, operr := GenerateOTSPrivateKey(LMOTSSHA256N32W1)
	if operr != nil {
		panic(operr)
	}
	// get the corresponding public key of lmotspriv
	lmotspub, oserr := lmotspriv.Public()
	if oserr != nil {
		panic(oserr)
	}
	// generate a LM-OTS signature
	lmotssig, osigerr := lmotspriv.Sign(message)
	if osigerr != nil {
		panic(osigerr)
	}
	// verify a LM-OTS signature
	overr := lmotspub.Verify(message, lmotssig)
	fmt.Println(overr)

	// ***************************************  LMS  ****************************************

	// generates a LMS private key with the types LMSSHA256M32H5 and LMOTSSHA256N32W1
	lmspriv, lperr := GenerateLMSPrivateKey(LMSSHA256M32H5, LMOTSSHA256N32W1)
	if lperr != nil {
		panic(lperr)
	}
	// get the corresponding public key of lmspriv
	lmspub, lserr := lmspriv.Public()
	if lserr != nil {
		panic(lserr)
	}
	// generate a LMS signature
	lmssig, lsigerr := lmspriv.Sign(message)
	if lsigerr != nil {
		panic(lsigerr)
	}
	// verify a LMS signature
	lverr := lmspub.Verify(message, lmssig)
	fmt.Println(lverr)

	// ***************************************  HSS  ****************************************

	// generates a 3-layer HSS private key with the types LMSSHA256M32H5 and LMOTSSHA256N32W1
	hsspriv, hperr := GenerateHSSPrivateKey(LMSSHA256M32H5, LMOTSSHA256N32W1, 3)
	if hperr != nil {
		panic(hperr)
	}
	// get the corresponding public key of hsspriv
	hsspub := hsspriv.Public()
	// generate a HSS signature
	hsssig, hsigerr := hsspriv.Sign(message)
	if hsigerr != nil {
		panic(hsigerr)
	}
	// verify a LMS signature
	hverr := hsspub.Verify(message, hsssig)
	fmt.Println(hverr)
	// Output:
	// <nil>
	// <nil>
	// <nil>
}
