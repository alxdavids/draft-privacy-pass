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
- Server: A service that provides access to a certain resource (sometimes
  denoted S)
- Client: An entity that seeks to authenticate to a server (sometimes denoted C)

## Layout

- {{utils}}: Details a list of utility objects and functions that are used in
  the generic protocol formulation.
- {{overview}}: A generic overview of the Privacy Pass protocol based on VOPRFs.
- {{crypto}}: Specific cryptographic instantiations of the Privacy Pass
  protocol.
- {{http}}: A formulation of the Privacy Pass in the HTTP setting, including
  marshaling and data transfer specifications.

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

### VOPRFParams {#voprfparams}

A `VOPRFParams` object is used to define the cryptographic parameters associated
with a particular VOPRF instantiation.

~~~
type VOPRFParams struct {
  secpar uint16
  id     uint16
  crs    []byte
  opts   []string
}
~~~

The field `secpar` refers to the minimum bits of security intended to be
provided by this parameter choice, `id` is a unique identifier for the object,
and `crs` is a sequence of random bytes that are used for verifying the
operations of the VOPRF. The field `opts` is reserved for optional strings that
configure the parameter set.

### VOPRFKey {#voprfkey}

A `VOPRFKey` object is used to define the cryptographic key that is used by the
server.

~~~
type VOPRFKey struct {
  params VOPRFParams
  secret VOPRFSecret
  public VOPRFPublic
  id     uint16
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
  params  VOPRFParams
  data    []byte
  created uint32
  expiry  uint32
}
~~~

The field `id` refers to a unique identifier for each public key. The field
`created` corresponds to the time when the key was created, and the field
`expiry` refers to the time when the key expires. We intentionally duplicate the
`params` field in the `VOPRFPublic` object, as this object can also act
independently of the `VOPRFKey` with which it is associated.

### Tokens

Token objects are the primary structures for holding data that is consumed
within the protocol. In particular, a `Token` is the object that is used to
authenticate a client to a server.

~~~
type Token struct {
  params     VOPRFParams
  data       []byte
}
~~~

Finally, a `BlindedToken` object is an abstract wrapper for a `TOken` that
is used by the client for acquiring the correct VOPRF evaluations.

~~~
type BlindedToken struct {
  oToken  Token
  bToken  Token
  blind   []byte
}
~~~

### VOPRFProof

A `VOPRFProof` object is used to assure the client that the server evaluated the
VOPRF honestly.

~~~
type VOPRFProof struct {
  data   []byte
  keyId  uint32
}
~~~

The variable `keyId` is essentially used to hold the ID of the public key
associated with the secret key used to generate the proof data.

### VOPRFOutput

A `VOPRFOutput` object is the principal output generated by the server during a
VOPRF protocol.

~~~
type VOPRFOutput struct {
  token Token
  proof VOPRFProof
}
~~~

### IssuedToken

An `IssuedToken` object is the principal output generated by a client after
authenticating with a server in the Privacy Pass protocol.

~~~
type IssuedToken struct {
  oToken      Token
  vToken      Token
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

The `Init` function takes a uint16 identifier as input and outputs a
`VOPRFParams` object.

~~~
func Init(id uint16) VOPRFParams
~~~

### KeyGen

The `KeyGen` function takes a `VOPRFParams` object as input and outputs a
`VOPRFKey` object.

~~~
func KeyGen(params VOPRFParams) VOPRFKey {
  secData := secretGen(params)
  pubData := publicGen(params, privData)
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
    params: params,
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
func secretGen(params VOPRFParams) []byte
~~~

~~~
func publicGen(params VOPRFParams) []byte
~~~

Any errors occurring during `KeyGen` should be considered fatal.

### TokenGen

The `TokenGen` function takes a `VOPRFParams` object as input, and outputs a
randomly generated `Token` object.

~~~
func TokenGen(params VOPRFParams) Token
~~~

### BlindedTokenGen

The `BlindedTokenGen` function takes a `VOPRFParams` object as input, and
outputs a new `BlindedToken` object.

~~~
func BlindedTokenGen(params VOPRFParams) BlindedTokenGen {
  oToken := TokenGen(params)
  blind := sampleBlind(params)
  bToken := constructBlindedToken(token, blind)
  return BlindedToken{
    oToken: oToken,
    bToken: bToken,
    blind: blind,
  }
}
~~~

The internal functions are defined as follows, along with the subsequent
function signatures.

- `sampleBlind` outputs a random sequence of bytes, depending on the input
  parameters.
- `constructBlindedToken` constructs a `Token` object, given a `Token` and
  a `blind` represented as a sequence of bytes as input.

~~~
func sampleBlind(params VOPRFParams) []byte
~~~

~~~
func constructBlindedToken(token Token, blind []byte) Token
~~~

### UnblindToken

The `UnblindToken` function takes as input a `Token` object and byte arrays
`blind`. It outputs a new `Token` object.

~~~
func UnblindToken(vt Token, blind []byte) Token {
  data := unblind(vt.params, vt.data, blind)
  return Token{
    params: vt.params
    data: data,
    compressed: vt.token.compressed
  }
}
~~~

The internal function `unblind` takes three `[]byte` inputs and outputs
`[]byte`:

~~~
func unblind(params VOPRFParams, vtData []byte, blind []byte) []byte
~~~

### VOPRFEval

The `VOPRFEval` function takes a `VOPRFKey` object and a `Token` object as
input; it outputs a `VOPRFOutput` object.

~~~
func VOPRFEval(key VOPRFKey, token Token) VOPRFOutput {
  output := evaluate(key, token)
  proof := prove(key, token, output)
  return VOPRFOutput{
    token: output,
    proof: proof,
  }
}
~~~

The internal functions are defined as follows:

~~~
func evaluate(key VOPRFKey, token Token) Token
~~~

~~~
func prove(key VOPRFKey, token Token, voprfEval Token) VOPRFProof
~~~

### VOPRFVerify

The `VOPRFVerify` function takes `VOPRFPublic`, `Token`, `VOPRFProof` objects as
input. It outputs a boolean value.

~~~
func VOPRFVerify(public VOPRFPublic, token Token, proof VOPRFProof) bool
~~~

### Redeem

The `Redeem` function takes two `Token` objects as input. It outputs a
`RedemptionData` object.

~~~
func Redeem(t Token, vt Token) RedemptionData {
  data := tag(t, vt)
  return RedemptionData{
    token: t,
    data: data,
  }
}
~~~

The internal function `tag` has the following signature.

~~~
func tag(t Token, vt Token) []byte
~~~

### RedeemVerify

The `RedeemVerify` function takes a `RedemptionData` object, a `VOPRFKey`
object. It outputs a boolean value.

~~~
func RedeemVerify(rd RedemptionData, key VOPRFKey) bool {
  chk := VOPRFEval(key, rd.token)
  return tagVerify(rd.token, chk, rd.data)
}
~~~

The internal function `tagVerify` has the following signature.

~~~
func tag(t Token, vt Token, data []byte) bool
~~~

## Error types

In the protocol overview that follows in {{overview}}, we enumerate a number of
error types that are triggered when certain events occur.

### UNKNOWN_PK_ERROR

Occurs when the public key that a server is using is not known on the
client-side.

### CLIENT_VERIFICATION_ERROR

Occurs when the client is unable to verify the proof sent by the server that it
has evaluated the VOPRF correctly.

### DOUBLE_SPEND_ERROR

Occurs if the server records a redemption request that contains a `Token` object
that has been observed previously.

### SERVER_VERIFICATION_ERROR

Occurs if the server fails to verify a redemption request sent by the client.

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
key pair. The public key generated by the server is sent to the client, and the
client stores the key for future usage.

~~~
C                                                 S
----------------------------------------------------------------------
                                                  id <-- SERVER_SUPPORTED_PARAMS
                                                  params := Init(id)
                                                  key := KeyGen(params)

                                key.public
                            <-------------------

public := key.public
params := public.params
if (!CLIENT_SUPPORTED_PARAMS.includes(params)) {
  panic(UNSUPPORTED_PARAMS_ERROR)
}
set(public.id, public)                            push(key)
~~~

In the protocol above, we use `CLIENT_SUPPORTED_PARAMS` and
`SERVER_SUPPORTED_PARAMS` both of types `[]uint16` to refer to the client's and
server's respective supported parameter sets. The notation:
```
id <-- SERVER_SUPPORTED_PARAMS
```
indicates that the server chooses some identifier from the list via any general
method.

## Issuance phase

The issuance phase allows the client to receive tokens from the server. On
successful completion of this phase, the client has authenticated to the server
and stored a token for future usage.

~~~
C                                       S
----------------------------------------------------------------------
                                        key

                        key.id
                  <-----------------

public := get(id)
if (public == nil) {
  panic(UNKNOWN_PK_ERROR)
}
params := public.params
bt1 := BlindedTokenGen(params)
vt := bt.token

                          vt
                  ------------------>

                                        out := VOPRFEval(key, vt.token)

                          out
                  <------------------

et := out.token
proof := out.proof
b := VOPRFVerify(public, et, proof)
if (!b) {
  panic(CLIENT_VERIFICATION_ERROR)
}

blind := bt1.blind
token := UnblindToken(et, blind)
is := IssuedToken{
  oToken: bt2.original
  vToken: token
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
                                      key

                    key.id
              <-------------------

public := get(id)
if (public == nil) {
  panic(UNKNOWN_PK_ERROR)
}
params := params.public

obj := pop(id)
ot := obj.oToken
vt := obj.vToken
rd := Redeem(ot, vt)

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
                                        b := RedeemVerify(rd, key)
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