+++
title = "Webring Project"
description = "A novel project for the new Java Spring stack: webrings!"
date = 2026-09-02
+++

Taking CS at Del Norte means you'll probably have a personal website at some point, hence the hundreds of student websites deployed over the years. There is, however, one particular gripe I have with the current system: it's really inconvenient to find other people's websites.

Wouldn't it be nice to have a network or platform to easily traverse classmates' websites? Theoretically, it could help build a sense of community within the CS enclave of DNHS and maybe some reminiscence of the old Internet.

There's a relatively simple way to do this, and has been tried and tested for decades. It has since then lost its novelty, but the rising IndieWeb has picked the practice back up. What I'm referring to is the humble _webring_.

Webrings, in the simplest sense, link websites together through... links. The idea is that some websites within a network link to each other, you eventually form a ring which connects all the websites one way or another:

![ring of websites](/images/webring.png)

There can also be a webring administrator who operates a central server which aggregates all of the websites and, alternatively, offers features like status checks, random routing, etc. Additionally, the presence of a central admin provides resilience to the network, so one website going down doesn't break the continuity of the ring.


## Roadmap

I won't really dwell on the technical implementations in depth, but there's a few features I want:

- **Interactive network graphs**, which supposedly indicate links between sites that don't pass through the main server. Think of something like a network visualization of badge wall connections.
- **Registry filters**, which show sites by year (course level like CSA, CSH, etc.).
- **Service trackers**, which record the basic accessibility of a site.


## Example

I was mainly inspired by a [NixOS webring](https://nixwebr.ing/), which pointed to some pretty cool websites and ran as a tiny Rust server. Of course, I'd actually be writing it in Java to integrate with Spring (don't worry!).
