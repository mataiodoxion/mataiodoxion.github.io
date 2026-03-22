+++
title = "Fock Flock"
description = "An idea for a nonprofit based project: fighting back against Flock."
date = 2026-03-19

[taxonomies]
tags = ["surveillance"]
+++

# Preface

Our CS teacher recently gave our class a project to collaborate (ultimately) with some nonprofit organization to do some good in the world. This would be completed in stages:

1. Brainstorming some improvements for that nonprofit's site;
2. Prototyping and pitching features/improvements;
3. Hopefully connecting and collaborating in the future as full time contributors.

# Flock

[Flock](https://en.wikipedia.org/wiki/Flock_Safety) is a company that builds surveillance systems explicitly intended to track people as they go about their daily lives. More specifically: they specialize in selling Automatic License Plater Readers (ALPRs) to track people, gunshot detection systems to listen to people, and person lookup tools to -- you guessed it -- stalk people.

Flock claims to scan over 2 billion license plates every month (great!), but it's also imperative to note that they're an explicit proponent of establishing a techno-fascist surveillance state. I don't mean this as a sort of exaggeration, I mean that their company mission is literally to create a national surveillance apparatus to sell to data brokers and government agencies.

### (No) Security 

Flock, for a company that handles highly sensitive information, does a pretty abysmal job of actually keeping that data safe. In fact, quite a few of their cameras were open to the internet to be exploited (with a weak default password, no password at all, or even no username!). Additionally, a _plethora_ of other security vulnerabilities were found by a number of researchers, as reported by [Benn Jordan](https://www.youtube.com/watch?v=uB0gr7Fh6lY). 

Flock responded by ~~fixing the security vulnerabilities~~ misleading their customers by saying their _cloud_ systems had not been leaked and shifting the blame to the customers themselves:

> #### Has Flock Been Hacked?
> No, Flock’s cloud platform has not been hacked. There has not been a leak of Flock information. [...]
> #### Has Flock Ever Had a Data Breach?
> No, Flock Safety’s cloud platform has never experienced a data breach, and no customer data has ever been compromised. [...]
> #### How Secure Are Flock's Cameras and Data?
> Customers decide how their data is used, not Flock. [...]
>
> — <cite>[Flock Safety](https://www.flocksafety.com/blog/has-flock-been-hacked), 6 January 2026</cite>

### Abuse

There have been a substantial number of documented cases of abuse. Operators (mainly police) of the ALPRs have used them to -- for example -- perform [warrantless surveillance](https://www.eff.org/deeplinks/2020/09/flock-license-plate-reader-homeowners-association-safe-problems), [stalk exes](https://apnews.com/general-news-699236946e3140659fff8a2362e16f43), [track women who had abortions (over state lines)](https://www.404media.co/a-texas-cop-searched-license-plate-cameras-nationwide-for-a-woman-who-got-an-abortion/), and [sell data to data brokers](https://inewsource.org/2022/01/06/police-share-license-plate-data/).

The abuses are endless and forthcoming when you make a web search every few days. It's no secret that the operators of the ALPRs skirt the law, while Flock really doesn't care _and_ enables them to do so by refusing to build in adequate safety measures.

### Flock Enables and Collaborates with Government Agencies (Especially ICE)

Flock denies the fact, but it's well documented:
- [ICE Taps into the Nationwide AI-Enabled Camera Network, Data Shows](https://www.404media.co/ice-taps-into-nationwide-ai-enabled-camera-network-data-shows/)
- [Police Unmask Millions of Surveillance Targets Because of Flock Redaction Error](https://www.404media.co/police-unmask-millions-of-surveillance-targets-because-of-flock-redaction-error/)
- [ICE, Secret Service, Navy All Had Access to Flock's Nationwide Network of Cameras](https://www.404media.co/ice-secret-service-navy-all-had-access-to-flocks-nationwide-network-of-cameras/)
- [Flock's Aggressive Expansions Go Far Beyond Simple Driver Surveillance](https://www.aclu.org/news/privacy-technology/flock-roundup)
- [California police are illegally sharing license plate data with ICE and border patrol](https://calmatters.org/economy/technology/2025/06/california-police-sharing-license-plate-reader-data/)
- etc, etc, etc.

Flock again denies that they collaborate with ICE and instead shift the blame to their customers:

> No. Flock does not work with U.S. Immigration and Customs Enforcement (ICE) ... Every piece of data collected by Flock license plate readers is owned and controlled by the customer, whether that customer is a city, county, school district, or private organization.
> 
> <cite>[Flock Safety](https://www.flocksafety.com/blog/does-flock-share-data-with-ice), 6 January 2026</cite>

The receipts are there. Flock shared data with CBP, ICE, and others then tried to lie about it. They do this all the time, and it's the same old story every single time.


## Warrantless Dragnet Surveillance

Flock as a system is, by definition, a system for warrantless dragnet surveillance. It works in two ways:
1. Flock sells ALPRs to local police departments and/or cities, who have cameras erected. The Flock cameras then record and process data about each person passing by (regardless of whether or not they're a criminal), then shares this data out without consent nationally (that is, it's integrated into a national database for anybody who pays to access).
2. Flock sells access to cameras and data directly. As with the case of ICE using Flock data to abduct people, Flock sells access to a "national lookup tool" which reportedly allows customers to input natural language, and Flock will pull up recordings which match that query. Again, it should be noted that Flock lied about selling data in this manner and collaborating with external agencies like ICE.

Dragnet surveillance simply is not worth the amount of freedom is completely removes compared to the miniscule benefit. The net benefit is in the negatives. In fact, Flock is really, _really_ ineffective at doing its job, and yet it still picks up billions of plates monthly. Those are billions of plates of innocent people being inducted into a national searchable database to be tracked without consent, without a warrant, and in violation of the constitution.

Let's take a look at San Diego: 

> Officers conducted more than 244,000 investigative searches of ALPR data, which played a key role in advancing 361 cases.
> 
> <cite>[San Diego Annual Surveillance Report 2025](https://www.sandiego.gov/sites/default/files/2026-02/sdpd-annual-surveillance-report-2025.pdf)</cite>

That's right! That's a 99.85% ineffective rate

Unless you want to live in a dystopian police state, there really isn't anything going for Flock (or unless you're some power hungry government actor).

## But Flock Helps Solve Cases!

Ok sure, Flock has helped with some cases, but these are the same type of cases that police have been solving for the last century. One could argue that setting up thousands of ALPRs for some chance to catch something could help with investigations (or has helped with a tiny amount), but police have been simply requesting already existing footage targeting specific areas for decades. It would be highly foolish to set up an entire surveillance apparatus that has been used to track people who have nothing to do with crime rather than focusing on targeted policing.

The problem with ALPRs and Flock is that they're a form of dragnet surveillance: they record everything that passes by and catch an overwhelming number of innocent people within that dragnet, making them vulnerable to abuse and control (as mentioned above). We should **not** be hooking up a nation wide system in a consolidated lookup tool, because that is quite literally a system intended explicitly for a "papers, please!" based authoritarian government. And we know this! They've been doing it for years, and yet most people simply don't care.

The emphasis here is _targeted_ policing. That means warrants, access requests, localization, etc. to protect the majority of people who are affected by these systems (who are generally innocent).

## Then What Alternative?

First, let's assume we keep these ALPR systems (e.g. Flock, Ubicquia, Motorola). The best case scenario you're going to get here is if jurisdiction is isolated to local communities. For example, San Diego -- one of the biggest and earliest adopters of ALPRs -- could restrict access to their data to exclusively their county... as opposed to funneling it directly into a national database and selling drivers' data. In this case, we keep the (little) benefit of a large dragnet surveillance system, while still maintaining some protections.

Naturally, we're still faced with problems of abuse (which comes with handing anybody the keys to a mass surveillance system) and the issue of Flock being unquestionably incompetent in relation to the data they handle. Thus, such an approach would require implementation of regulations including judicial warrants in addition to security updates to disconnect from the Flock network nationally. It's not too clear if this is possible at all, and given the motive for the systems in the first place, it's clear that Flock is in fact intended to be a drop-in mass surveillance system, so it's pretty futile to try implementing these protections given the people running the show.

So, the best alternative here is really just to erase the entire system. Quite frankly, it's too volatile to keep a mass surveillance sitting around in the first place; even if you place protections, there are malicious actors who will abuse it anyway. For instance, back in 2014, an Executive Order (12,333) gave NSA the authority to spy on foreign soil; that is, protections at the time existed to protect domestic citizens on domestic soil, but the NSA had free reign to conduct surveillance on foreign soil. To no one's surprise, the NSA simply tapped into domestic international calls and continued to spy on American citizens. 

Or, perhaps better known, Section 702 of the Foreign Intelligence Surveillance Act (FISA) allows the warrantless surveillance and intends to only target foreign citizens outside of the US. To surveil an American citizen, the government would have to acquire either a warrant. Yet, all the three letter agencies still conducts tens of thousands of illegal searches of Americans (including phone calls, emails, texts, browsing). 

Case in point, when the explicit (or implicit) intent of a system is to spy on people, and the people who are turning the gears to make it run are people who want to spy on you, then they probably are trying to spy on you. Historically, layering protections on top of that generally won't work because they're so damn adamant about spying on people. The whole thing is rotten to its core so long as the motive exists. As such, more "feature updates" and "transparency reports" (Flock) aren't going to help people; the people who actually use these systems are people who have a very strong motive to surveil people, and they have demonstrated so countless times. It's high time to throw the entire thing out.
