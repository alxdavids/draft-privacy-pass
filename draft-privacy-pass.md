---
title: The Privacy Pass Protocol
abbrev: PP protocol
docname: draft-privacy-pass-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: A. Davidson
    name: Alex Davidson
    org: Cloudflare, UK
    street: County Hall, Belvedere Road
    city: London
    country: United Kingdom
    email: adavidson@cloudflare.com

normative:
  RFC2119:
  DGSTV18:
    title: Privacy Pass, Bypassing Internet Challenges Anonymously
    target: https://www.degruyter.com/view/j/popets.2018.2018.issue-3/popets-2018-0026/popets-2018-0026.xml
    authors:
      -
        ins: A. Davidson
        org: RHUL, UK
      -
        ins: I. Goldberg
        org: University of Waterloo, Canada
      -
        ins: N. Sullivan
        org: Cloudflare, CA, USA
      -
        ins: G. Tankersley
        org: Independent
      -
        ins: F. Valsorda
        org: Independent
  OPRF:
    title: Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups
    target: https://tools.ietf.org/html/draft-sullivan-cfrg-voprf-03
    authors:
      -
        ins: A. Davidson
        org: Cloudflare, UK
      -
        ins: N. Sullivan
        org: Cloudflare, US
      -
        ins: C. Wood
        org: Apple Inc.
  PPEXT:
    title: Privacy Pass Browser Extension
    target: https://github.com/privacypass/challenge-bypass-extension
  PPSRV:
    title: Cloudflare Supports Privacy Pass
    target: https://blog.cloudflare.com/cloudflare-supports-privacy-pass/

--- abstract

This document specifies the Privacy Pass protocol for anonymously
authenticating to services on the internet.

--- middle

# Introduction

In some situations, it may only be necessary to check that a client has
previously authenticated to a service; without learning any other information.
Such lightweight authentication mechanisms can be useful in quickly assessing
the reputation of a client in latency-sensitive communication.

The Privacy Pass protocol was initially introduced as a mechanism for
authenticating clients that had previously demonstrated their `honesty`
{{DGSTV18}}. In particular, the Cloudflare content delivery network (CDN)
has implemented server-side support for the Privacy Pass protocol {{PPSRV}}. This
support allows clients to bypass security mechanisms, providing that they have
successfully passed these mechanisms previously. There is also a client-side
implementation in the form of a browser extension that interacts with the
Cloudflare network {{PPEXT}}.

The main security requirement of the Privacy Pass protocol is to ensure that
previously authenticated clients do not reveal their identity on
reauthentication. The protocol uses a cryptographic primitive known as a
verifiable oblivious pseudorandom function (VOPRF) for implementing the
authentication mechanism. In particular, the VOPRF is constructed in prime-order
groups that allow it to be implemented using elliptic curve cryptography
{{OPRF}}.

In this document, we will give a formal specification of the Privacy Pass
protocol in the internet setting. In particular, we will specify how
communication is achieved over HTTP, comparisons with different functionality
and efficiency configurations, as well as strategies for performing secure key
rotation.

## Terminology

The following terms are used throughout this document.

- PRF: Pseudorandom function
- VOPRF: Verifiable oblivious PRF
- Server: A service that provides access to a certain resource
- Client: An entity that seeks to authenticate to a server

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in {{RFC2119}}.

# Utilities {#utils}

In this section, we will give an exhaustive list of all the data structures and
functions that we will use throughout the protocol in {{overview}}.

## Data structures {#structs}

We describe the data structures that we use for storing and transferring
information.

### VOPRFKey {#voprfkey}

A VOPRFKey object is used to define the cryptographic key that is used by the
server.

~~~
type VOPRFKey struct {
  secret VOPRFSecret
  public VOPRFPublic
}
~~~

The VOPRFSecret object defines the secret portion of the key.

~~~
type VOPRFSecret struct {
  data []byte
}
~~~

The VOPRFPublic object defines the public portion of the key.

~~~
type VOPRFPublic struct {
  data    []byte
  id      uint32
  created uint32
  expiry  uint32
}
~~~

The field `id` refers to a unique identifier for each public key. The field
`created` corresponds to the time when the key was created, and the field
`expiry` refers to the time when the key expires.

### Tokens

Token objects are the primary structures for holding data that is consumed
within the protocol. In particular, a `Token` is the object that is used to
authenticate a client to a server.

~~~
type Token struct {
  data       []byte
  compressed bool
}
~~~

A `VOPRFToken` object is the principal input type that is used as the
clients input in a VOPRF protocol.

~~~
type VOPRFToken struct {
  token Token
  id    uint32
}
~~~

The field `id` is a unique identifier for each `VOPRFToken` object. We will
assume that a `Token` object can be transformed into `VOPRFToken` object by just
instantiating with a dummy identifier.

Finally, a `BlindedToken` object is an abstract wrapper for a `VOPRFToken` that
is used by the client for acquiring the correct VOPRF evaluations.

~~~
type BlindedToken struct {
  original Token
  token    VOPRFToken
  blind    []byte
}
~~~

### VOPRFProof

A `Proof` object is used to assure the client that the server evaluated the
VOPRF honestly.

~~~
type VOPRFProof struct {
  data   []byte
  public VOPRFPublic
}
~~~

### VOPRFOutput

A `VOPRFOutput` object is the principal output generated by the server during a
VOPRF protocol.

~~~
type VOPRFOutput struct {
  token VOPRFToken
  proof VOPRFProof
}
~~~

### IssuedToken

An `IssuedToken` object is the principal output generated by a client after
authenticating with a server in the Privacy Pass protocol.

~~~
type IssuedToken struct {
  token      Token
  voprfToken VOPRFToken
}
~~~

### RedemptionData

A `RedemptionData` object is the principal object type sent by a client to
reauthenticated with a server, after a successful previous authentication.

~~~
type RedemptionData struct {
  token Token
  data  []byte
}
~~~

### RedemptionResp

A `RedemptionResp` object is the principal object type returned from the server
to the client, indicating whether a redemption was successful or not.

~~~
type RedemptionResp struct {
  resp bool
  err  error
}
~~~

If `resp == true`, then `err == nil`. Otherwise, `err` should be populated with
the correct error type.

## Common functions {#funcs}

We now detail a selection of functions that we will use throughout the protocol.

### Init

The `Init` function takes a length (or security) parameters, and a common
description as a sequence of bytes as input and outputs public auxiliary data in
the form of an array of bytes.

~~~
func Init(secParameter uint16, common []byte) []byte
~~~

### KeyGen

The `KeyGen` function takes a length (or security) parameter, and some public
auxiliary data as input and outputs a `VOPRFKey` object.

~~~
func KeyGen(secParameter uint16, auxData []byte) VOPRFKey {
  secData := secretGen(secParameter, auxData)
  pubData := publicGen(secParameter, auxData, privData)
  created := currDate()
  expiry := exprDate()
  id := idGen(auxData, pubData)

  public := VOPRFPublic{
    data: pubData,
    id: id,
    created: created,
    expiry: expiry,
  }

  secret := VOPRFSecret{
    data: secData
  }

  return VOPRFKey{
    secret: secret,
    public: public
  }
}
~~~

The internal functions used in `KeyGen` are defined in the following way:

- `currDate` returns the current date/time
- `expiryDate` returns the corresponding expiry date/time
- `secretGen` returns a sequence of bytes that will be used as the secret
  portion of the key
- `publicGen` returns a sequence of bytes that will be as the public portion of
  the key

The `secretGen` and `publicGen` function statements are defined below.

~~~
func secretGen(secParameter uint16, auxData []byte) []byte
~~~

~~~
func publicGen(secParameter uint16, auxData []byte) []byte
~~~

Any errors occurring during `KeyGen` should be considered fatal.

### TokenGen

The `TokenGen` function takes the security and auxiliary parameters as inputs,
and outputs a randomly generated `Token` object.

~~~
func TokenGen(secParameter uint16, auxData []byte) Token
~~~

### BlindedTokenGen

The `BlindedTokenGen` function takes the security and auxiliary parameters as
inputs, and outputs a new `BlindedToken` object.

~~~
func BlindedTokenGen(secParameter uint16, auxData []byte) BlindedTokenGen {
  token := TokenGen(secParameter, auxData)
  blind := sampleBlind(secParameter, auxData)
  voprfToken := constructBlindedToken(token, blind, auxData)
  return BlindedToken{
    original: token,
    token:    voprfToken,
    blind:    blind,
  }
}
~~~

The internal functions are defined as follows, along with the subsequent
function signatures.

- `sampleBlind` outputs a random sequence of bytes, depending on the security
  and auxiliary data parameters that are provides
- `constructBlindedToken` constructs a `VOPRFToken` object, given a `Token` and
  a `blind` represented as a sequence of bytes.

~~~
func sampleBlind(secParameter uint16, auxData []byte) []byte
~~~

~~~
func constructBlindedToken(token Token, blind []byte, auxData []byte) VOPRFToken
~~~

### UnblindToken

The `UnblindToken` function takes as input a `VOPRFToken` object and byte arrays
`blind` and `auxData`. It outputs a new `Token` object.

~~~
func UnblindToken(vt VOPRFToken, blind []byte, auxData []byte) Token {
  data := unblind(vt.data, blind, auxData)
  return Token{
    data: data,
    compressed: vt.token.compressed
  }
}
~~~

The internal function `unblind` takes three `[]byte` inputs and outputs
`[]byte`:

~~~
func unblind(vtData []byte, blind []byte, auxData []byte) []byte
~~~

### VOPRFEval

The `VOPRFEval` function takes a `VOPRFKey`, a `VOPRFToken` and auxiliary data
as input, and outputs a `VOPRFOutput` object.

~~~
func VOPRFEval(key VOPRFKey, token VOPRFToken, auxData []byte) VOPRFOutput {
  output := evaluate(key, token, auxData)
  proof := prove(key, token, output, auxData)
  return VOPRFOutput{
    token: output,
    proof: proof,
  }
}
~~~

The internal functions are defined as follows:

~~~
func evaluate(key VOPRFKey, token VOPRFToken, auxData []byte) VOPRFToken
~~~

~~~
func prove(key VOPRFKey, token VOPRFToken, voprfEval VOPRFToken, auxData []byte) VOPRFProof
~~~

### VOPRFVerify

The `VOPRFVerify` function takes `VOPRFPublic`, `VOPRFToken`, `VOPRFProof`
objects, and auxiliary data as input. It outputs a boolean value.

~~~
func VOPRFVerify(public VOPRFPublic, token VOPRFToken, proof VOPRFProof, auxData []byte) bool
~~~

### Redeem

The `Redeem` function takes a `Token` object, a `VOPRFToken` object, the
security parameter and auxiliary data as input. It outputs a `RedemptionData`
object.

~~~
func Redeem(t Token, vt VOPRFToken, secParameter uint16, auxData []byte) RedemptionData {
  data := tag(t, vt, secParameter, auxData)
  return RedemptionData{
    token: t,
    data: data,
  }
}
~~~

The internal function `tag` has the following signature.

~~~
func tag(t Token, vt VOPRFToken, secParameter uint16, auxData []byte) []byte
~~~

### RedeemVerify

The `RedeemVerify` function takes a `RedemptionData` object, a `VOPRFKey`
object, the security parameter and auxiliary data as input. It outputs a boolean
value.

~~~
func RedeemVerify(rd RedemptionData, key VOPRFKey, secParameter uint16, auxData []byte) bool {
  chk := VOPRFEval(key, rd.token, auxData)
  return tagVerify(rd.token, chk, rd.data, secParameter, auxData)
}
~~~

The internal function `tagVerify` has the following signature.

~~~
func tag(t Token, vt VOPRFToken, data []byte, secParameter uint16, auxData []byte) bool
~~~

# Overview of protocol {#overview}

In this document, we will be assuming that a client (C) is attempting to
authenticate itself in a lightweight manner to a server (S). The authentication
mechanism should not reveal to the server anything about the client; in
addition, the client should not be able to forge valid credentials in situations
where it does not possess any.

In this section, we will give a broad overview of how the Privacy Pass protocol
functions in achieving these goals. The generic protocol can be split into three
phases: initialisation, issuance and redemption. In this protocol description we
make use of the utility functions displayed in {{utils}}.

We will give details on the specific cryptographic instantiation of this
protocol in {{crypto}}. We will also specify how to instantiate the protocol in
the HTTP setting specifically in {{http}}.

## Initialisation phase

In the initialisation phase, we assume that there is some common description
which is available to both parties (described as a sequence of bytes). We will
denote this common description by `crs`. Both C and S are also aware of the
security parameter `sp`.

The initialisation (or init) phase consists of the server generating their VOPRF
key pair, both participants also generate the auxiliary data for the protocol.

~~~
C                                         S
----------------------------------------------------------------------
crs, sp                                 crs, sp
auxData := Init(sp, auxData)            auxData := Init(sp, crs)
                                        key := KeyGen(sp, auxData)
return auxData                          return key, auxData
~~~

## Issuance phase

The issuance phase allows the client to receive tokens from the server. On
successful completion of this phase, the client has authenticated to the server
and stored a token for future usage.

~~~
C                                         S
----------------------------------------------------------------------
auxData, sp                               key, auxData, sp
bt1 := BlindedTokenGen(sp, auxData)
vt := bt.token
set(vt.id, bt)

                            vt
                  -------------------->

                                          out := VOPRFEval(key, token, auxData)

                            out
                  <--------------------

et := out.token
proof := out.proof
public := proof.public
b := VOPRFVerify(public, et, proof, auxData)
if (!b) {
  panic(CLIENT_VERIFICATION_ERROR)
}

bt2 := get(et.id)
blind := bt2.blind
if (blind == nil) {
  panic(UNKNOWN_ID_ERROR)
}

token := UnblindToken(et, blind, auxData)
is := IssuedToken{
  token: bt2.original
  voprfToken: token
}
push(is)
~~~

## Redemption phase

The redemption phase allows the client to reauthenticate to the server, using a
token that it has received from a previous issuance phase. The security of the
VOPRF ensures that the client's identity cannot be linked to any of the previous
issuance phases.

~~~
C                                     S
----------------------------------------------------------------------
auxData, sp                           key, auxData, sp
obj := pop()
ot := obj.token
vt := obj.voprfToken
rd := Redeem(ot, vt, sp, auxData)

                        rd
              -------------------->

                                      d := get(token)
                                      resp := true
                                      err := nil

                                      if (d) {
                                        resp = false
                                        err = DOUBLE_SPEND_ERROR
                                      }

                                      if (resp) {
                                        b := RedeemVerify(rd, key, sp, auxData)
                                        if (!b) {
                                          resp = false
                                          err = SERVER_VERIFICATION_ERROR
                                        }
                                      }

                                      set(token, true)
                                      rr := RedemptionResp{
                                        resp: resp
                                        err: err
                                      }

                        rr
              <--------------------

~~~

# Cryptographic instantiation {#crypto}

TODO: give cryptographic description of VOPRF from generic protocol based on
{{OPRF}}.

# HTTP instantiation {#http}

TODO: give a specific instantiation of the protocol in the HTTP setting.