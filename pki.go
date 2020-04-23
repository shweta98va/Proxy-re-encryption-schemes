package main

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"randstring"
	"crypto/sha512"
)

//User Structure comprising secret key and public key
type User struct {
	sk *big.Int
	pk *big.Int
}

type Cipher1 struct{
	C1 *big.Int
	C2 *big.Int
	C3 []byte
	C4 *big.Int
}

type Cipher2 struct{
	D1 *big.Int
	D2 []byte
}

type Params struct{
	p *big.Int
	q *big.Int
	g *big.Int
	lm int
}

type Cipher_ struct{
	C1_ *big.Int
	C2_ *big.Int
}

type Valid struct{
	r *big.Int
	u *big.Int
}

//--------------------------------------------------------------Hash Functions--------------------------------------------------------------

//---------------------------------------------------H1: Maps to an element in cyclic group-------------------------------------------------

func hash1 (m []byte, w []byte) (*big.Int){
	h := sha512.New()
	if _, err := h.Write(m); err != nil {
		panic(err)
	}
	if _, err := h.Write(w); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int)
	r.SetBytes(h1)
	return r
}

//---------------------------------------------------H2: Maps to an element in cyclic group-------------------------------------------------

func hash2 (pkI *big.Int, C1 *big.Int) (*big.Int){
	h := sha512.New()
	if _, err := h.Write(pkI.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int)
	r.SetBytes(h1)
	return r
}

//----------------------------------------------------------H3: Maps to a string------------------------------------------------------------

func hash3 (G *big.Int) ([]byte){
	h := sha512.New()
	if _, err := h.Write(G.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1
}

//---------------------------------------------------H4: Maps to an element in cyclic group-------------------------------------------------

func hash4 (C1 *big.Int, C2 *big.Int, C1_ *big.Int, C2_ *big.Int, C3 []byte, pkI *big.Int) (*big.Int){
	h := sha512.New()
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C2.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1_.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C2_.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C3); err != nil {
		panic(err)
	}
	if _, err := h.Write(pkI.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int)
	r.SetBytes(h1)
	return r
}

//----------------------------------------------------------------Setup-------------------------------------------------------------------

func Setup (params Params) (Params) {
	params.p = big.NewInt(458669)
	params.q = big.NewInt(16381)
	params.g = big.NewInt(16379)
	
	return params
}

//-----------------------------------------------------------Key Generation----------------------------------------------------------------

func KeyGen (user User, params Params) (User){
	sk , err := rand.Int(rand.Reader, params.q) 					//Secret Key calculation : A random value x within Zq*
	if err != nil {
		panic(err)
	}
	user.sk = sk
	user.pk = new(big.Int).Exp(params.g, user.sk, params.q)				//Public key calculation : g^x
	return user
}

//----------------------------------------------------Re-Encryption Key Generation----------------------------------------------------------

func ReKeyGen (userI User, userJ User) (*big.Int){	
	var rekey = new(big.Int).Div(userJ.sk, userI.sk)				//rekey(i->j) = xj/xi
	return rekey
}

//-----------------------------------------------------------Encryption--------------------------------------------------------------------

func Encrypt (m []byte, user User, params Params, C Cipher1, C_ Cipher_, V Valid) (Cipher1, Cipher_,  Valid){
	var l1 = 0
	if(params.lm < 64){
		l1 = 64 - params.lm
	}

	u, err := rand.Int(rand.Reader, params.q) 					//Selection of a random u value
	if err != nil {
		panic(err)
	}
	V.u = u

	const charset = "01"
	w := []byte(randstring.StringWithCharset(l1, charset)) 				//Generating random padding string
	V.r = new(big.Int).Mod(hash1(m,w), params.q)					// r = H1(m,w)
	fmt.Println(user.pk, V.r)
	
	C.C1 = new(big.Int).Exp(user.pk, V.r, params.q) 				// C1 = pkI^r
	var t = hash2(user.pk, C.C1)
	C_.C1_ = new(big.Int).Exp(t, V.r, params.q)					// C1_ = H2(pkI, C1)^r
	
	s, err := rand.Int(rand.Reader, params.q) 					//Selection of a random u value
	if err != nil {
		panic(err)
	}
	C.C2 = new(big.Int).Exp(user.pk, s, params.q) 					// C2 = pkI^s
	C_.C2_ = new(big.Int).Exp(hash2(user.pk, C.C1), s, params.q) 			// C2_ = H2(pkI, C1)^s

	var mw = append(m[:], w[:]...)
	var z = new(big.Int).Exp(params.g, V.r, params.q)
	fmt.Println("Z", z)
	var hash = hash3(new(big.Int).Exp(params.g, V.r, params.q))
	var c3 [64]byte
	for i := 0; i < 64; i++ {
		c3[i] = mw[i] ^ hash[i] 						// C3 = m||w xor H3(g^r)
	}
	C.C3 = append(C.C3[:], c3[:]...)

	h := hash4(C.C1, C.C2, C_.C1_, C_.C2_, C.C3, user.pk) 				// h = H4(C1, C2, C1_, C2_, C3, pkI)
	var t1 = new(big.Int).Mul(V.u, h)
	var t2 = new(big.Int).Add(V.r, t1)

	C.C4 = new(big.Int).Mod(t2, params.q) 						// C4 = (r + uh) mod q

	//fmt.Println(C.C1, C.C2, C.C3, C.C4, C_.C1_, C_.C2_, V.r, V.u)
	return C, C_, V
}

//---------------------------------------------------------Validation Check------------------------------------------------------------

func Validity(C Cipher1, C_ Cipher_, user User, V Valid, params Params) (*big.Int){
	h := hash4(C.C1, C.C2, C_.C1_, C_.C2_, C.C3, user.pk) 				// h = H4(C1, C2, C1_, C2_, C3, pkI)
	var t1 = new(big.Int).Mul(V.u, h)
	var t2 = new(big.Int).Add(V.r, t1)
	var v = new(big.Int).Mod(t2, params.q) 						//v = (r + uh) mod q
	return v
}

//------------------------------------------------------------Re-Encrypt----------------------------------------------------------------

func ReEncrypt(C Cipher1, D Cipher2, C_ Cipher_, rekey *big.Int, user User, V Valid, params Params ) (Cipher2){
	var v = Validity(C, C_, user, V, params)
	if(v.Cmp(C.C4) == 0){
		D.D1 = new(big.Int).Exp(C.C1, rekey, nil)				// D1 = C1^rekey
		D.D2 = append(D.D2[:], C.C3[:]...)					// D2 = C3
	}
	//fmt.Println()
	//fmt.Println(D.D1, D.D2)
	return D
}

//-------------------------------------------------------------Decrypt-----------------------------------------------------------------

func Decrypt(C Cipher1, C_ Cipher_, user User, V Valid, params Params) () {
	//var v = Validity(C, C1_, C2_, pkI, u, r, q)
	//if(bytes.Compare(v, C.C4) == 0){
		//var skInv = new(big.Int).ModInverse(skI, q); // Inverse secret key xi^-1

		var skInv = new(big.Int).ModInverse(user.sk, params.q)
		var I =  new(big.Int).Mod(new(big.Int).Mul(user.sk, skInv), params.q)
		fmt.Println(user.sk, skInv, I)
		var T = new(big.Int).Exp(C.C1, skInv, params.q)
		fmt.Println("T ",T)
		
		/*c1 := new(big.Int)
		c1.SetBytes(C.C1) 
		var T = (new(big.Int).Exp(c1, skInv, nil)) // T=C1^xi^-1
		var t = T.Bytes()
		var hash = hash3(t)
		var mw [64]byte
		for i := 0; i < 64; i++ {
			mw[i] = hash[i] ^ C.C3[i] //  m||w = H3(T) xor C3
		}
				
		var m = mw[ : length]
		//var w = mw[length + 1:]	//Slice to m and w
		//if (bytes.Compare(C.C1, (new(big.Int).Exp(pkI,hash1(m,w),q)).Bytes()) == 0){
			return m //if c1= H1(m,w) return m else nil
		//}
	//}*/
	//return nil
}

//---------------------------------------------------------------------Re-Decrypt-------------------------------------------------------------------

func ReDecrypt(D Cipher2, user User, params Params) () {
	/*//var skInv = new(big.Int).Exp(skJ, big.NewInt(-1), nil)
	var skInv = new(big.Int).ModInverse(skJ, q);
	d1 := new(big.Int)
	d1.SetBytes(D.D1) 
	var T = (new(big.Int).Exp(d1, skInv, q)).Bytes()//T=D1^xj^-1
	var hash = hash3(T)
	var mw [64]byte
	for i := 0; i < 64; i++ {
		mw[i] = hash[i] ^ D.D2[i] //  m||w = H3(T) xor D2
	}
	var m = mw[:length]
	//var w = mw[length+1:] //Slice to m and w
	//if (bytes.Compare(D.D1, hash1(m,w).Bytes()) == 0){
		return m //H1(m,w)=D1 then return m else null
	//}
	//return nil*/
}


func main() {
	var params Params
	m := []byte("Hello World, How are you.")
	params.lm = len(m)
	var userI, userJ User
	var rekey *big.Int
	var C Cipher1
	var C_ Cipher_
	var V Valid
	var D Cipher2

	params = Setup(params)

	userI = KeyGen(userI, params)
	userJ = KeyGen(userJ, params)

	rekey = ReKeyGen(userI, userJ)
	
	C, C_, V = Encrypt(m, userI, params, C, C_, V)

	D = ReEncrypt(C, D, C_, rekey, userI, V, params)

	Decrypt(C, C_, userI, V, params)

	ReDecrypt(D, userJ, params)

	var G = big.NewInt(501)
	var Q = big.NewInt(301)
	var S = big.NewInt(401)
	var R = big.NewInt(601)
	var P = new(big.Int).Exp(G, S, nil)
	var C1 = new(big.Int).Exp(P, R, nil)
	var GR = new(big.Int).Exp(G, R, Q)
	var sInv = new(big.Int).ModInverse(S, Q)
	var T = new(big.Int).Exp(C1, sInv, Q)
	fmt.Println(sInv, GR, T)
	var t = new(big.Int).Mul(R, S)
	var t1 = new(big.Int).Mul(t, sInv)
	var t2 = new(big.Int).Exp(G, t1, Q)
	fmt.Println(t, t1, t2)
	
	/*fmt.Println()
	fmt.Println("Public Key of Delegator I  : ",userI.pk)
	fmt.Println("Private Key of Delegator I : ",userI.sK)
	fmt.Println()
	fmt.Println("Public Key of Delegatee J  : ",userI.pk)
	fmt.Println("Private Key of Delegatee J : ",userI.sK)
	fmt.Println()*/
