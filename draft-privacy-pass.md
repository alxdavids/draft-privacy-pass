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
has implemented server-side support for the Privacy Pass protocol {{PSRV}}. This
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

# Overview of protocol {#overview}

In this document, we will be assuming that a client (C) is attempting to
authenticate itself in a lightweight manner to a server (S). The authentication
mechanism should not reveal to the server anything about the client; in
addition, the client should not be able to forge valid credentials in situations
where it does not possess any.

In this section, we will give a broad overview of how the Privacy Pass protocol
functions in achieving these goals. We detail the protocol in the HTTP setting.

## Data structures {#structs}

We describe the data structures that we use for storing and transferring
information.

### VOPRFKey {#voprfkey}

A VOPRFKey object is used to define the cryptographic key that is used by the
server.

```go
type VOPRFKey struct {
  voprf_sk VOPRFSecret
  voprf_pk VOPRFPublic
}
```

The VOPRFSecret object defines the secret portion of the key.

```go
type VOPRFSecret struct {
  data []byte
}
```

The VOPRFPublic object defines the public portion of the key.

```go
type VOPRFPublic struct {
  data    []byte
  id      uint32
  created uint32
  expiry  uint32
}
```

The field `id` refers to a unique identifier for each public key. The field
`created` corresponds to the time when the key was created, and the field
`expiry` refers to the time when the key expires.

### Tokens

Token objects are the primary structures for holding data that is consumed
within the protocol. In particular, a `Token` is the object that is used to
authenticate a client to a server.

```go
type Token struct {
  data       []byte
  compressed bool
}
```

A `BlindedToken` object is used by a client for acquiring authentication Tokens
during the protocol.

```go
type BlindedToken struct {
  token Token
  blind []byte
  id    uint32
}
```

The field `id` is a unique identifier for each BlindedToken object.

## Common functions {#funcs}

