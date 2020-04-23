package main

import (
	"fmt"
	"crypto/rand"
	"randstring"
	"math/big"
	"crypto/sha512"
	"floatToint"
	"strconv"
	"math"
	"time"
)

type Params struct {
	q *big.Int
	P *big.Int
	Ppub *big.Int
	l0 int
	l1 int
	lID int
}

type PartialPublicKey struct {
	X *big.Int
	Y *big.Int
	d *big.Int
}

type PartialSecretKey struct{
	y *big.Int
}

type UserPublicKey struct {
	Z *big.Int
}

type UserSecretKey struct {
	z *big.Int
}

type PublicKey struct {
	X *big.Int
	Y *big.Int
	Z *big.Int
	d *big.Int
}

type SecretKey struct {
	z *big.Int	
	y *big.Int
}

type User struct {
	ID []byte
	PPK PartialPublicKey
	PSK PartialSecretKey
	UPK UserPublicKey
	USK UserSecretKey
	PK PublicKey
	SK SecretKey
}

type ReKey struct{
	a *big.Int
	b *big.Int
	V *big.Int
	W *big.Int
}

type Cipher1 struct {
	C1 *big.Int
	C2 *big.Int
	C3 []byte
	C4 *big.Int
}

type Cipher_ struct{
	C1_ *big.Int
	C2_ *big.Int
}

type Cipher2 struct {
	D1 *big.Int
	D2 *big.Int
	D3 []byte
	D4 *big.Int
	D5 *big.Int
}


//------------------------------------------------------------------Hashes------------------------------------------------------------

//----------------------------------------------------H: Maps to an element in cyclic group-------------------------------------------

func hash_ (ID []byte, C1 *big.Int, C1_ *big.Int, C3 []byte) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(ID); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1_.Bytes()); err != nil {
		panic(err)
	}
if _, err := h.Write(C3); err != nil {
