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
    target: https://tools.ietf.org/html/draft-irrf-cfrg-voprf-01
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
  DSS:
    title: "FIPS PUB 186-4: Digital Signature Standard (DSS)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    author:
      -
        ins: Federal Information Processing Standards Publication

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
groups. In particular, this allows it to be implemented using elliptic curves
{{OPRF}}.

In this document, we will give a formal specification of the Privacy Pass
protocol in the internet setting. In particular, we will specify how
communication is achieved over HTTP, comparisons with different functionality
and efficiency configurations, and how the OPRF protocol should be integrated
into the wider Privacy Pass protocol workflow.

## Terminology

The following terms are used throughout this document.

- PRF: Pseudorandom function
- VOPRF: Verifiable oblivious PRF {{OPRF}}
- Server: A service that provides access to a certain resource (sometimes
  denoted S)
- Client: An entity that seeks to authenticate to a server (sometimes denoted C)

## Preliminaries

Throughout this draft, let D be some object corresponding to an opaque data type
(such as a group element). We write []byte(D) to denote the encoding of this
data type as raw bytes. For two objects x and y, we denote the concatenation of
the bytes of these objects by ([]byte(x) .. []byte(y)). We assume that all
bytes are first base64-encoded before they are sent as part of a protocol
message.

## Layout

- {{overview}}: A generic overview of the Privacy Pass protocol based on VOPRFs.
- {{crypto}}: Specific cryptographic instantiations of the Privacy Pass
  protocol.
- {{http}}: A formulation of the Privacy Pass in the HTTP setting, including
  marshaling and data transfer specifications.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in {{RFC2119}}.

# Overview of protocol {#overview}

In this document, we will be assuming that a client (C) is attempting to
authenticate itself in a lightweight manner to a server (S). The authentication
mechanism should not reveal to the server anything about the client; in
addition, the client should not be able to forge valid credentials in situations
where it does not possess any.

In this section, we will give a broad overview of how the Privacy Pass protocol
functions in achieving these goals. The generic protocol can be split into three
phases: initialisation, issuance and redemption. In particular, a large part of
the operations that we require are specified as part of existing VOPRF
functionality {{OPRF}}. We adhere to the recommendations laid out in {{OPRF}} in
integrating the VOPRF protocol into our wider workflow. Where necessary, we lay
out exactly which VOPRF API functionality we use.

## Key initialisation phase

In the initialisation phase, essentially we run the VOPRF setup phase in that
the server runs VOPRF_Setup(l) where l is the required bit-length of the prime
used in establishing the order of the group GG. This outputs the tuple (k,Y,p)
where: p = p(l) is the prime order of GG = GG(l); k is a uniformly sampled
element from GF(p); and Y = kG for some fixed generator of GG.

However, the server must first come to an agreement on what group instantiation
to support. This involves choosing an instantiation with the required security
level implied by the choice of l. The server has a list of supported group
params (GROUP_PARAMS) and chooses an identifier, id, associated with the
preferred group configuration, and also outputs the implied length of l. It
creates a Privacy Pass key object denoted by ppKey that has fields "private",
"public" and "group". It sets ppKey.private = []byte(k), ppKey.public =
[]byte(Y) and ppKey.group = id.

The server creates a JSON object of the form below.

~~~
{
  "Y": pp_key.public
  "expiry": <expiry_date>
  "sig": <signature>
}
~~~

The field "expiry" corresponds to an expiry date for the newly sampled key. We
recommend that each key has a lifetime of between 1 month and 1 year. The field
"sig" holds an ASN1-encoded ECDSA signature evaluated over the contents of "Y"
and "expiry". The ECDSA parameters should be equivalent to the group
instantiation used for the OPRF, and the signing key (ecdsaSK) should be
long-term with a corresponding publicly available verification key (ecdsaVK). We
summarize the creation of this object using the algorithm PP_key_init(), which
we define below.

~~~
function PP_key_init(k, Y, id) {
  ppKey.private = []byte(k)
  ppKey.public = []byte(Y)
  ppKey.group = id
  var today = new Date()
  var expiry = today.setMonth(today.getMonth() + n);
  var obj = {
    Y: ppKey.public,
    expiry: expiry,
    sig: ECDSA.sign(ecdsaSK, ppKey.public .. []byte(expiry)),
    id: id,
  }
  return [ppKey, obj]
}
~~~

Note that the variable n above should correspond to the number of months ahead
that the expiry date should correspond to.

We give a diagrammatic representation of the initialisation phase below.

~~~
C(ecdsaVK)                                        S(ecdsaSK)
----------------------------------------------------------------------
                                                  l = GROUP_PARAMS[id]
                                                  (k,Y,p) = VOPRF_Setup(l)
                                                  [ppKey,obj] = PP_key_init(k,Y,id)

                                     obj
                            <-------------------

public := key.public
if (!ECDSA.verify(ecdsaVK, obj.Y .. []byte(obj.expiry)) {
  panic(ECDSA_VERIFICATION_FAILED)
} else if (!(new Date() < obj.expiry)) {
  panic(COMMITMENT_EXPIRED_ERROR)
}
store(obj.id, obj.public)                            push(key)
~~~

The variable obj essentially corresponds to a cryptographic commitment to the
server's VOPRF key. We abstract all signing and verification of ECDSA signatures
into the ECDSA.sign and ECDSA.verify functionality {{DSS}}.

### Trusted registry

Rather than sending the result of the key initialisation procedure directly to
each client, it is preferable to upload the object obj to a trusted,
tamper-proof, history-preserving registry. By trusted, we mean from the
perspective of clients that use the Privacy Pass protocol. Any new keys uploaded
to the registry should be appended to the list. Any keys that have expired can
optionally be labelled as so, but should never be removed. A trusted registry
may hold key commitments for multiple Privacy Pass service providers (servers).

Clients can either choose to:

- poll the trusted registry and import new keys, rejecting any that throw
  errors;
- retrieve the commitments for the server at the time at which they are used,
  throwing errors if no valid commitment is available.

To prevent unauthorized modification of the trusted registry, server's should be
required to identify and authenticate themselves before they can append data to
their configuration. Moreover, only parts of the registry that correspond to the
servers configuration can be modifiable.

### Key rotation

Whenever a server seeks to rotate their key, they must append their key to the
trusted registry. We recommend that the trusted registry is arranged as a JSON
blob with a member for each JSON provider. Each provider appends new keys by
creating a new sub-member corresponding to an incremented version label along
with their new commitment object.

Concretely, we recommend that the trusted registry is a JSON file of the form
below.

~~~
{
  "server_1": {
    "1.0": {
      "Y": ...,
      "expiry": ...
      "sig": ...
    },
    "1.1": {
      "Y": ...,
      "expiry": ...
      "sig": ...
    },
  }
  "server_2": {
    "1.0": {
      "Y": ...,
      "expiry": ...
      "sig": ...
    },
  },
  ...
}
~~~

In this structure, "server_1" and "server_2" are separate service providers. The
sub-members "1.0", "1.1" of "server_1" correspond to the versions of commitments
available to the client. Increasing version numbers should correspond to newer
keys. If "server_2" wants to upload a new commitment with version tag "1.1", it
runs the key initialisation procedure from above and adds a new sub-member "1.1"
with the value set to the value of the output obj. The "server_2" member should
now take the form below.

~~~
{
  ...
  "server_2": {
    "1.0": {
      "Y": ...,
      "expiry": ...
      "sig": ...
    },
    "1.1": {
      "Y": ...,
      "expiry": ...
      "sig": ...
    },
  },
  ...
}
~~~

### Key revocation

If a server must revoke a key, then it uses a separate member with label
"revoke" corresponding to an array of revoke versions associated with key
commitments. In the above example, if "server_2" needs to revoke the key with
version "1.0", then it appends a new "revoke" member with the array [ "1.0" ].
Any future revocations can simply be appended to this array. For an example, see
below.

~~~
{
  ...
  "server_2": {
    "1.0": {
      "Y": ...,
      "expiry": ...
      "sig": ...
    },
    "1.1": {
      "Y": ...,
      "expiry": ...
      "sig": ...
    },
    "revoked": [ "1.0" ],
  },
  ...
}
~~~

Client's are required to check the "revoked" member for new additions when they
poll the trusted registry for new key data.

### ECDSA key material

For clients must also know the verification (ecdsaVK) for each service provider
that they support. This enables the client to verify that the commitment is
properly formed before it uses it. We do not provide any specific
recommendations on how the client has access to this key, beyond that the
verification key should be accessible separately from the trusted registry.

While the number of service providers associated with Privacy Pass is low, the
client can simply hardcode the verification keys directly for each provider that
they support. This may be cumbersome if a provider wants to rotate their signing
key, but since these keys should be comparatively long-term (relative to the
VOPRF key schedule), then this should not be too much of an issue.

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