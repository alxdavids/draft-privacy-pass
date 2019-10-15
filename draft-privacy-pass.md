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
  TRUST:
    title: Trust Token API
    target: https://github.com/WICG/trust-token-api#security-considerations
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
{{OPRF}}. The protocol is split into three stages. The first two stages,
initialisation and evaluation, are essentially equivalent to the VOPRF setup and
evaluation phases from {{OPRF}}. The final stage, redemption, essentially
amounts to revealing the client's secret inputs in the VOPRF protocol. The
security (pseudorandomness) of the VOPRF protocol means that the client retains
their privacy even after revealing this data.

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
(such as a group element). We write bytes(D) to denote the encoding of this
data type as raw bytes. We assume that such objects can also be interpreted as
Buffer objects, with each internal slot in the buffer set to the value of the
one of the bytes. For two objects x and y, we denote the concatenation of the
bytes of these objects by (bytes(x) .. bytes(y)). We assume that all bytes are
first base64-encoded before they are sent as part of a protocol message.

We use the notation `[ Ti ]` to indicate an array of objects T1, ... , TQ where
the size of the array is Q, and the size of Q is implicit from context.

## Layout

- {{overview}}: A generic overview of the Privacy Pass protocol based on VOPRFs.
- {{exts}}: Extensions to the Privacy Pass protocol that allow for more specific
  functionality.
- {{privacy}}: Privacy considerations and recommendations arising from the
  usage of the Privacy Pass protocol.
- {{security}}: Additional security considerations to prevent abuse of the
  protocol from a malicious client.
- {{encoding}}: Valid data encodings for all objects that are in transit during
  the protocol.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in {{RFC2119}}.

# Generalized protocol overview {#overview}

In this document, we will be assuming that a client (C) is attempting to
authenticate itself in a lightweight manner to a server (S). The authentication
mechanism should not reveal to the server anything about the client; in
addition, the client should not be able to forge valid credentials in situations
where it does not possess any.

In this section, we will give a broad overview of how the Privacy Pass protocol
functions in achieving these goals. The generic protocol can be split into three
phases: initialisation, issuance and redemption. As we mentioned previously, the
first two stages are essentially identical to the setup and evaluation phases of
the VOPRF in {{OPRF}}. The last stage, redemption, corresponds to the client
revealing their secret input data during the VOPRF protocol to the server. The
server can use this data to confirm that the client has a valid VOPRF output,
without being able to link the data to any individual issuance phase.

Throughout this document we adhere to the recommendations laid out in {{OPRF}}
in integrating the VOPRF protocol into our wider workflow. Where necessary, we
lay out exactly which VOPRF API functionality we use. We stress that the
generalized protocol only includes steps and messages that contain cryptographic
data. In {{browser}}, we discuss how to implement the protocol in the browser
setting, along with appropriate message encodings and formats.

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
"public" and "group". It sets ppKey.private = bytes(k), ppKey.public =
bytes(Y) and ppKey.group = id.

The server creates a JSON object of the form below.

~~~ json
  {
    "Y": pp_key.public,
    "expiry": <expiry_date>,
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

~~~ js
  function PP_key_init(k, Y, id) {
    ppKey.private = bytes(k)
    ppKey.public = bytes(Y)
    ppKey.group = id
    var today = new Date()
    var expiry = today.setMonth(today.getMonth() + n);
    var obj = {
      Y: ppKey.public,
      expiry: expiry,
      sig: ECDSA.sign(ecdsaSK, ppKey.public .. bytes(expiry)),
    }
    return [ppKey, obj]
  }
~~~

Note that the variable n above should correspond to the number of months ahead
that the expiry date should correspond to.

We give a diagrammatic representation of the initialisation phase below.

~~~
    C(ecdsaVK)                                S(ecdsaSK)
    ----------------------------------------------------------------------
                                              l = GROUP_PARAMS[id]
                                              (k,Y,p) = VOPRF_Setup(l)
                                              [ppKey,obj] = PP_key_init(k,Y,id)

                                obj
                        <-------------------

    public := key.public
    if (!ECDSA.verify(ecdsaVK, obj.Y .. bytes(obj.expiry)) {
      panic(ECDSA_VERIFICATION_FAILED)
    } else if (!(new Date() < obj.expiry)) {
      panic(COMMITMENT_EXPIRED_ERROR)
    }
    store(obj.id, obj.public)                            push(key)
~~~

The variable obj essentially corresponds to a cryptographic commitment to the
server's VOPRF key. We abstract all signing and verification of ECDSA signatures
into the ECDSA.sign and ECDSA.verify functionality {{DSS}}.

In the initialisation phase above, we require that the server contacts each
viable client. In {{registry}} we discuss the possibility of uploading public
key material to a trusted registry that client's access when communicating with
the server.

## Issuance phase

The issuance phase allows the client to receive VOPRF evaluations from the
server. The issuance phase essentially corresponds to a VOPRF evaluation phase
{{OPRF}}. In essence, the client generates a valid VOPRF input x (a sequence of
bytes from some unpredictable distribution), and runs the VOPRF evaluation phase
with the server. The client receives an output y of the form:

~~~ lua
    dk = H_2("voprf_derive_key", x .. bytes(N))
    y = H_2(dk, aux)
~~~

where H_2 is a function defined in {{OPRF}} that is modeled as a random oracle,
N is a group element, and aux is auxiliary data that is generated by the client.
More specifically, N is an unblinded group element equal to k*H_1(x) where H_1
is a random oracle that outputs elements in GG. The client stores (x, y) as
recommended in {{OPRF}}. We give a diagrammatic overview of the protocol below.

~~~
    C(x, aux)                                 S(ppKey)
    ----------------------------------------------------------------------
    var ciph = retrieve(S.id, "ciphersuite")
    var (r,M) = VOPRF_Blind(x)

                          bytes(M)
                      ------------------>

                                            (Z,D) = VOPRF_Eval(ppKey.private,
                                                ciph.G,Y,M)
                                            var resp = {
                                              element: bytes(Z),
                                              proof: bytes(D),
                                              version: "key_version",
                                            }

                              resp
                      <------------------

    var elt = resp.element
    var proof = resp.proof
    var version = resp.version
    var obj = retrieve(S.id, version)
    if obj == "error" {
      panic(INVALID_COMMITMENT_ERROR)
    }
    var N = VOPRF_Unblind(G,Y,M,elt,proof)
    var y = VOPRF_Finalize(x,N,aux)
    if (y == "error") {
      panic(CLIENT_VERIFICATION_ERROR)
    }

    push((ciph,x,y,aux))
~~~

In the diagram above, the client knows the VOPRF ciphersuite supported by the
server when it retrieves in the first step. It uses this information to
correctly perform group operations before sending the first message.

## Redemption phase

The redemption phase allows the client to reauthenticate to the server, using
data that it has received from a previous issuance phase. By the security of the
VOPRF, even revealing the original input x that is used in the issuance phase
does not affect the privacy of the client. In other words, no server should be
able to link a client redemption request to any particular with issuance phase,
except for negligible probability.

~~~
    C()                                     S(ppKey)
    ----------------------------------------------------------------------
    var ciph1 = retrieve(S.id, "ciphersuite")
    a = pop()
    while (a != undefined) {
      (ciph2,x,y,aux) = a
      if (ciph1 != ciph2) {
        // ciphersuites do not match
        a = pop()
        continue
      }
    }
    if (!a) {
      // no valid data to redeem
      return
    }

                        (x,y,aux)
                  -------------------->

                                          if (store.includes(x)) {
                                            panic(DOUBLE_SPEND_ERROR)
                                          }
                                          T = H1(x)
                                          N' = OPRF_Eval(ppKey.private, T)
                                          y' = OPRF_Finalize(x,N',aux)
                                          resp = (y' == y)
                                              ? "success"
                                              : "failure"
                                          store.push(x)

                          resp
                  <--------------------

    output resp
~~~

Note that the server uses the API provided by OPRF_Eval and OPRF_Finalize,
rather than the corresponding VOPRF functions. This is because the VOPRF
functions also compute zero-knowledge proof data that we do not require at this
stage of the protocol.

### Double-spend protection

To protect against clients that attempt to spend a value x more than once, the
server uses an index, store, to collect valid inputs and then check against in
future protocols. Since this store needs to only be optimized for storage and
querying, a structure such as a Bloom filter suffices. Importantly, the server
must only eject this storage after a key rotation occurs since all previous
client data will be rendered obsolete after such an event.

## Error types {#errors}

# Key registration {{registry}}

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

## Key rotation

Whenever a server seeks to rotate their key, they must append their key to the
trusted registry. We recommend that the trusted registry is arranged as a JSON
blob with a member for each JSON provider. Each provider appends new keys by
creating a new sub-member corresponding to an incremented version label along
with their new commitment object.

Concretely, we recommend that the trusted registry is a JSON file of the form
below.

~~~ json
  {
    "server_1": {
      "ciphersuite": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "1.1": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
    }
    "server_2": {
      "ciphersuite": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
    },
    ...
  }
~~~

In this structure, "server_1" and "server_2" are separate service providers. The
sub-member "ciphersuite" corresponds to the choice of VOPRF ciphersuite made by
the server. The sub-members "1.0", "1.1" of "server_1" correspond to the
versions of commitments available to the client. Increasing version numbers
should correspond to newer keys. Each commitment should be a valid encoding of a
point corresponding to the group in the VOPRF ciphersuite specified in
"ciphersuite".

If "server_2" wants to upload a new commitment with version tag "1.1", it runs
the key initialisation procedure from above and adds a new sub-member "1.1" with
the value set to the value of the output obj. The "server_2" member should now
take the form below.

~~~ json
  {
    ...
    "server_2": {
      "ciphersuite": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "1.1": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
    },
    ...
  }
~~~


## Client retrieval

We define a function retrieve(server_id, version_id) which retrieves the
commitment with version label equal to version_id, for the provider denoted by
the string server_id. For example, retrieve("server_1","1.1") will retrieve the
member labelled with "1.1".

We implicitly assume that this function performs the following verification
checks:

~~~ lua
  if (!ECDSA.verify(ecdsaVK, obj.Y .. bytes(obj.expiry)) {
    return "error"
  } else if (!(new Date() < obj.expiry)) {
    return "error"
  }
~~~

If "error" is not returned, then it instead returns the entire object. We also
abuse notation and also use ciph = retrieve(server_id, "ciphersuite") to refer
to retrieving the ciphersuite for the server configuration.

## Key revocation

If a server must revoke a key, then it uses a separate member with label
"revoke" corresponding to an array of revoke versions associated with key
commitments. In the above example, if "server_2" needs to revoke the key with
version "1.0", then it appends a new "revoke" member with the array [ "1.0" ].
Any future revocations can simply be appended to this array. For an example, see
below.

~~~ json
  {
    ...
    "server_2": {
      "ciphersuite": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "1.1": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "revoked": [ "1.0" ],
    },
    ...
  }
~~~

Client's are required to check the "revoked" member for new additions when they
poll the trusted registry for new key data.

## VOPRF ciphersuites

Following the recommendations in {{OPRF}}, we assume that a server uses only one
VOPRF ciphersuite at any one time. Should a server choose to change some aspect
of the ciphersuite (e.g., the group instantiation or other cryptographic
functionality)  we recommend that the server create a new identifying label
(e.g. "server_1_${ciphersuite_id}") where ciphersuite_id corresponds to the
identifier of the VOPRF ciphersuite. Then "server_1" revokes all keys for the
previous ciphersuite and then only offers commitments for the current label.

An alternative arrangement would be to add a new layer of members between server
identifiers and key versions in the JSON struct, corresponding to
ciphersuite_id. Then the client may choose commitments from the appropriate
group identifying member.

We strongly recommend that service providers only operate with one group
instantiation at any one time. If a server uses two VOPRF ciphersuites at any
one time then this may become an avenue for segregating the user-base. User
segregation can lead to privacy concerns relating to the utility of the
obliviousness of the VOPRF protocol (as raised in {{OPRF}}). We discuss this
more in ...

## ECDSA key material

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

# Extensions {#exts}

TODO: Discuss some of the possible extensions of Privacy Pass.

# Privacy considerations {#privacy}

We intentionally encode no special information into Trust Tokens to prevent a
vendor from learning anything about the client. We also have cryptographic
guarantees via the VOPRF construction that a vendor can learn nothing about a
client beyond which issuers trust it. Still there are ways that malicious
servers can try and learn identifying information about clients that it
interacts with.

We discuss a number of privacy considerations made in {{OPRF}} that are
relevant to the Privacy Pass protocol use-case, along with additional
considerations arising from the browser integration.

## User segregation

An inherent features of using cryptographic primitives like VOPRFs is that any
client can only remain private relative to the entire space of users using the
protocol. In principle, we would hope that the server can link any client
redemption to any specific issuance invocation with a probability that is
equivalent to guessing. However, in practice, the server can increase this
probability using a number of techniques that can segregate the user space into
smaller sets.

### Key rotation

As introduced in {{OPRF}}, such techniques to introduce segregation are closely
linked to the type of key schedule used by the server. When a server rotates
their key, any client that invokes the issuance protocol shortly afterwards will
be part of a small number of possible clients that can redeem. To mechanize this
attack strategy, a server could introduce a fast key rotation policy which would
force clients into small key windows. This would mean that client privacy would
only have utility with respect to the smaller group of users that have Trust
Tokens for a particular key window.

In the {{OPRF}} draft it is recommended that great care is taken over key
rotations, in particular server's should only invoke key rotation for fairly
large periods of time such as between 1 and 12 months. Key rotations represent a
trade-off between client privacy and continued server security. Therefore, it is
still important that key rotations occur on a fairly regular cycle to reduce the
harmfulness of a server key compromise.

Trusted registries for holding Privacy Pass key commitments can be useful in
policing the key schedule that a server uses. Each key must have a corresponding
commitment in this registry so that clients can verify issuance responses from
servers. Clients may choose to inspect the history of the registry before first
accepting Trust Tokens from the server. If a server has updated the registry
with many unexpired keys, or in very quick intervals a client can choose to
reject the tokens.

TODO: Can client's flag bad server practices?

### Large numbers of issuers {#issuers}

Similarly to the key rotation issue raised above, if there are a large number of
issuers, similar user segregation can occur. In the proposed browser
integration, a vendor OV can choose to invoke trust attestations for more than
one issuer. Each SRR that a client holds essentially corresponds to a bit of
information about the client that OV can learn. Therefore, there is an
exponential loss in privacy relative to the number of issuers that there are.

For example, if there are 32 issuers, then OV learns 32 bits of information
about the client. If the distribution of issuer trust is anything close to a
uniform distribution, then this is likely to uniquely identify any client
amongst all other internet users. Assuming a uniform distribution is clearly the
worst-case scenario, and unlikely to be accurate, but it provides a stark
warning against allowing too many issuers at any one time.

#### Selected trusted registries

One recommendation is that only a fixed number (TODO: how many?) of issuers are
sanctioned to provide Trust Tokens at any one time. This could be enforced by
the trusted registry that is being used. Client's can then choose which
registries to trust and only accept Trust Tokens from issuers accepted into
those registries.

#### Maximum number of issuers inferred by client

A second recommendation is that clients only store Trust Tokens for a fixed
number of issuers at any one time. This would prevent a malicious vendor from
being able to invoke redemptions for many issuers since the client would only be
holding Trust Tokens for a small set of issuers. When a client is issued tokens
from a new issuer and already has tokens from the maximum number of issuers, it
simply deletes the oldest set of Trust Tokens in storage and then stores the
newly acquired tokens.

#### Enforcing limits on per-origin issuances and redemptions

Finally it may be possible for browsers to enforce a strict limit on the number
of redemption requests that can be made by a vendor. Such limits may also be
worthwhile enforcing for the number issuances that can be invoked per origin.

The number of redemptions and issuances that have occurred can be persisted in
browser storage either related to the origin, or via temporal information. This
would prevent certain origins from being able to invoke numerous instances of
either protocol phase.

## Tracking and identity leakage

While Trust Tokens themselves encode no information about the client redeeming
them, there may be problems if we allow too many redemptions on a single page.
For instance, the first-party cookie for user U on domain A can be encoded in
the trust token information channel and decoded on domain B, allowing domain B
to learn the user's domain A cookie until either first-party cookie is cleared.

Mitigations for this issue are similar to those proposed in {{issuers}} for
tackling the problem of having large number of issuers.

Moreover, cached SRRs and their associated browser public keys have a similar
tracking potential to first party cookies. Therefore these should be clearable
by browser’s existing Clear Site Data functionality.The SRR and its public key
are untamperable first-party tracking vectors. They allow sites to share their
first-party user identity with third parties on the page in a verifiable way. To
mitigate this potentially undesirable situation, user agents can request
multiple SRRs in a single token redemption, each bound to different key pairs,
and use different SRRs and key pairs when performing requests based on the
third-party or over time.

In order to prevent the issuer from binding together multiple simultaneous
redemptions, the UA can blind the key pairs before sending them to the issuer.
Additionally, the client may need to produce signed timestamps to prevent the
issuer from using the timestamp as another matching method.

# Security considerations {#security}

We present a number of security considerations that prevent a malicious actors
from abusing the protocol.

## Double-spend protection

All issuing server should implement a robust storage-query mechanism for
checking that tokens sent by clients have not been spent before. Such tokens
only need to be checked for each issuer individually. But all issuers must
perform global double-spend checks to avoid clients from exploiting the
possibility of spending tokens more than once against distributed token checking
systems. For the same reason, the global data storage must have quick update
times. While an update is occurring it may be possible for a malicious client to
spend a token more than once.

## Key rotation

We highlighted previously that short key-cycles can be used to reduce client
privacy. However, regular key rotations are still recommended to maintain good
server key hygiene. The key material that we consider to be important are:

- the VOPRF key;
- the signing key used to sign commitment information;
- the signing key used to sign SRRs.

In summary, our recommendations are that VOPRF keys are rotated from anywhere
between a month and a single year. With an active user-base, a month gives a
fairly large window for clients to participate in the Privacy Pass protocol and
thus enjoy the privacy guarantees of being part of a larger group. The low
ceiling of a year prevents a key compromise from being too destructive. If a
server realizes that a key compromise has occurred then the server should revoke
the previous key in the trusted registry and specify a new key to be used.

For the two signing keys, these should both be well-known keys associated with
the issuer (TODO: where should they be stored?). Issuers may choose to use the
same key for both signing purposes. The rotation schedules for these keys can be
much longer, if necessary.

## Token exhaustion

To prevent a vendor from exhausting all the tokens that a client for a given (or
multiple) issuers, we recommend the following mitigations.

- Issuers issue many tokens at once, so users have a large supply of tokens.
- Browsers will only ever redeem one token per top-level page view, so it will
  take many page views to deplete the full supply.
- The browser will cache SRRs per-origin and only refresh them when an issuer
  iframe opts-in, so malicious origins won't deplete many tokens. The
  "freshness" of the SRR becomes an additional trust signal.
- Browsers may choose to limit redemptions on a time-based schedule, and either
  return cached SRRs if available, or require consumers to cache the SRR.
- Issuers will be able to see the Referer, subject to the page's referrer
  policy, for any token redemption, so they'll be able to detect if any one site
  is redeeming suspiciously many tokens.


# Valid data encodings {#encoding}

TODO: Discuss valid data encodings of all objects in transport.