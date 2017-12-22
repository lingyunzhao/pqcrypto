# pqcrypto

pqcrypto -- A post-quantum cryptography library

# Installation

* requirements: `go get -u golang.org/x/crypto/...`
* install: `go get -u github.com/lingyunzhao/pqcrypto/...`

# Documentation

See [Go  Doc](https://godoc.org/github.com/lingyunzhao/pqcrypto) or [Go Walker](https://gowalker.org/github.com/lingyunzhao/pqcrypto) for usage and details.

# Hash-based signatures

## Lamport-Diffie-Winternitz-Merkle (LDWM) scheme

Standards: [draft-mcgrew-hash-sigs-08](https://datatracker.ietf.org/doc/draft-mcgrew-hash-sigs/)

* LM-OTS One-Time Signatures
* Leighton Micali Signatures
* Hierarchical signatures

## eXtended Merkle Signature Scheme (XMSS)

Standards: [draft-irtf-cfrg-xmss-hash-based-signatures-10](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)

* WOTS+ One-Time Signatures
* XMSS: eXtended Merkle Signature Scheme
* XMSS^MT: Multi-Tree XMSS

## Miscellaneous

* LDWM and XMSS are both stateful hash-based signatures. Signing reads a private key and a message and generates a signature but also generates an updated private key. Make sure to update the back-up private key before shutdown the program. You can use `String()` method to serialize a key and `ParseXXX()` to recover the key from a string.
* The merkle tree traversal algorithm used in LDWM and XMSS are in log space and time according to [Szydlo04](https://iacr.org/archive/eurocrypt2004/30270536/szydlo-loglog.pdf).
* The runtimes of some high security signature types in LDWM and XMSS are very long. However, weaker security signature types such as `LMSSHA256M32H10` in LDWM-LMS and `XMSSSHA2H16W256` in XMSS-XMSS are enough for security consideration.

# TODO

* implement the stateless hash-based signatures scheme __SPHINCS__
* improve performance
* implement other post-quantum cryptography schemes
