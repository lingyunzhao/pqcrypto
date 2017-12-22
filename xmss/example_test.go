// Copyright 2017 Lingyun Zhao. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmss

import (
	"fmt"
)

func Example() {
	// test message
	message := []byte("Hello, world!")

	// ***************************************  XMSS  ****************************************

	// generates an XMSS key pair with the type XMSSSHA2H10W256
	xsk, xpk, xkerr := KeyGen(XMSSSHA2H10W256)
	if xkerr != nil {
		panic(xkerr)
	}
	// generate an XMSS signature
	xsig, xserr := xsk.Sign(message)
	if xserr != nil {
		panic(xserr)
	}
	// verify an XMSS signature
	xver := xpk.Verify(message, xsig)
	fmt.Println(xver)

	// *************************************** XMSS^MT ***************************************

	// generates an XMSS^MT key pair with the type XMSSMTSHA2H20D4W256
	mtsk, mtpk, mkerr := MTkeyGen(XMSSMTSHA2H20D4W256)
	if mkerr != nil {
		panic(mkerr)
	}
	// generate an XMSS^MT signature
	mtsig, mserr := mtsk.Sign(message)
	if mserr != nil {
		panic(mserr)
	}
	// verify an XMSS^MT signature
	mver := mtpk.Verify(message, mtsig)
	fmt.Println(mver)
	// Output:
	// true
	// true
}
