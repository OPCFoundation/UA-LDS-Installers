# EU Cyber Resilience Act — Compliance Documentation

Regulation (EU) 2024/2847. This directory holds the compliance artifacts for the
OPC UA Local Discovery Server.

## Position

**OPC Federation AISBL publishes the LDS as free and open-source software under
the MIT License, acting as an open-source software steward under Article 24.**

That determination sets the scope of everything here. As a steward, and not a
manufacturer, we are **not** subject to:

- CE marking or the EU declaration of conformity
- Conformity assessment under any Annex VIII module
- The Annex VII technical documentation file
- Administrative fines (Article 64(10)(b))
- The Annex I Part I essential requirements as directly binding obligations

We **are** subject to:

| Obligation | Where satisfied |
|---|---|
| Art. 24(1) — documented cybersecurity policy, verifiable | [`cybersecurity-policy.md`](cybersecurity-policy.md) |
| Art. 24(1) — foster voluntary vulnerability reporting (Art. 15) | [`/SECURITY.md`](../../SECURITY.md) |
| Art. 24(2) — cooperate with market surveillance authorities | `cybersecurity-policy.md` §8 |
| Art. 24(3) → Art. 14(1) — report actively exploited vulnerabilities | [`reporting-runbook.md`](reporting-runbook.md) Trigger A |
| Art. 24(3) → Art. 14(3), (8) — report severe incidents affecting development infrastructure | `reporting-runbook.md` Trigger B |

The SBOM in [`/sbom`](../../sbom) is not strictly a steward obligation — it sits
in Annex I Part II(1), which binds manufacturers. We produce it regardless,
because it is the only practical basis for the vulnerability monitoring that
Article 24(1) *does* require, and because downstream integrators who embed the
LDS need it for their own compliance.

### Residual risk in this position

Recorded so the decision is reviewable rather than assumed.

The CRA excludes free and open-source software not supplied in the course of a
commercial activity, and Article 24 exists precisely because open-source products
are *published* rather than *made available on the market*. The fact most likely
to be challenged in our case is that **we distribute a signed, pre-compiled MSI
installer**, not only source code. Related factors: OPC Foundation charges
membership fees, and the LDS underpins a commercial ecosystem.

If that position were ever rejected, the consequence would be the manufacturer
track — Annex I Part I, technical documentation, CE marking, and conformity
assessment — with a further question about whether bundling a certificate
generator engages Annex III Class I item 9 ("public key infrastructure and
digital certificate issuance software").

**That second question is still open.** An earlier version of this document
said the certificate generator rewrite would remove it. It does not: the
rewrite (gap 1) replaced the end-of-life OpenSSL, but the tool still issues
certificates in-process — it builds, signs and stores X.509 certificates
itself rather than delegating to a system `openssl.exe`. It is therefore just
as much "digital certificate issuance software" as the version it replaced.

What would actually remove the question is **not shipping it inside the MSI** —
distributing it as a separate download instead. That is a packaging decision,
not an engineering one, and worth considering on its own merits: the tool is
not used by the discovery service at runtime, so nothing in the LDS needs it
present.

**Recommendation:** have counsel confirm the steward determination in writing,
and keep that confirmation with these documents. The engineering work in this
directory is useful under either reading, so it should not wait on the opinion.

## Timeline

Article 71(2): *"This Regulation shall apply from 11 December 2027. However,
Article 14 shall apply from 11 September 2026 and Chapter IV (Articles 35 to 51)
shall apply from 11 June 2026."*

| Date | Applies to us? | What |
|---|---|---|
| 10 Dec 2024 | — | CRA entered into force |
| 11 Jun 2026 | no | Chapter IV — notification of conformity assessment bodies |
| 11 Sep 2026 | **not as a steward** | Article 14 reporting, for **manufacturers**. ENISA Single Reporting Platform live |
| **11 Dec 2027** | **yes** | Article 24, and with it our Article 14(1)/(3)/(8) duties via Article 24(3) |

**Our reporting duty begins 11 December 2027, not now** — because Article 14
binds *manufacturers* by its own terms, a steward is by definition not a
manufacturer, and the provision extending Article 14 to stewards is Article
24(3), which is covered by the general 11 December 2027 date.

Two things follow, and they matter more than the extra runway:

- **The role risk and the date risk are the same risk.** If the steward
  determination below were rejected, we would be a manufacturer — and the
  manufacturer obligation has been live since 11 September 2026, not 2027. An
  aggressive reading of our role makes the obligation retroactively live. This
  is the strongest practical argument for getting the determination confirmed in
  writing.
- **We operate [`reporting-runbook.md`](reporting-runbook.md) now regardless.**
  Article 15 voluntary reporting is open to anyone today, and reporting
  capability cannot be assembled inside a 24-hour window.

This reading is interpretive rather than a Commission holding — see the caveat
in the runbook header.

## Document index

| Document | Contents |
|---|---|
| [`cybersecurity-policy.md`](cybersecurity-policy.md) | The Article 24(1) policy. Secure development, dependency management, vulnerability handling, records, known gaps |
| [`reporting-runbook.md`](reporting-runbook.md) | Article 14 operational runbook. Triggers, 24/72/14 deadlines, SRP mechanics, incident checklist |
| [`cve-policy.md`](cve-policy.md) | Vulnerability identifiers: GCVE-105, what earns one, third-party components, and how this differs from Article 14 |
| [`/SECURITY.md`](../../SECURITY.md) | Public-facing disclosure policy |
| [`/.well-known/security.txt`](../../.well-known/security.txt) | RFC 9116 machine-readable contact record (must be deployed to the domain to take effect) |
| [`/sbom/README.md`](../../sbom/README.md) | SBOM design, per-project ownership, composition |

## What is done

- Article 24(1) cybersecurity policy, version-controlled in-repo ("verifiable manner")
- Public vulnerability disclosure policy with private intake, response targets, scope, and honest disclosure of the two known component problems
- Article 14 reporting runbook covering both steward triggers, with SRP registration mechanics and an incident checklist
- Per-project component inventories: each repository (`UA-LDS`, `UA-LDS-mDNSResponder`, and this one) declares only what it produces and links, with PURLs, CPEs, licenses and CVE-monitoring strategy. Each publishes its own SBOM; the installer's is **composed** from them, deduplicated, with SHA-256 back-links to each source document
- Attack-surface mapping (`cybersecurity-policy.md` §1.1), carried into each SBOM as a `cra:exposure` property and into `SECURITY.md` so reporters arrive with calibrated severity
- CycloneDX 1.6 generator wired into `build.ps1`, resolving submodule commits and binary digests at build time; SBOMs ship in the release ZIP
- Known gaps recorded with planned actions (`cybersecurity-policy.md` §7)
- **Gap 1 closed:** the certificate generator was rewritten in C against the
  LDS's own OpenSSL 3.5.7, removing the end-of-life OpenSSL 1.1.1w and the
  entire second OpenSSL build from the product. Every shipped component now
  links one current crypto library, so a single advisory assessment covers the
  whole product

## Open items — input needed

The documents contain `<<TBD: ...>>` markers keyed to these numbers. Items 1–5
block publication of the documents as they stand.

| # | Needed | Why it blocks | Lands in |
|---|---|---|---|
| 1 | ~~**Security contact address**~~ — **RESOLVED.** `securityteam@opcfoundation.org`, with the PGP key published in [OPCFoundation/OPC-SecurityAdvisories](https://github.com/OPCFoundation/OPC-SecurityAdvisories). Taken from the existing OPC Foundation advisory programme rather than invented. | — | `SECURITY.md`, `/.well-known/security.txt` |
| 2 | **Support period and supported versions.** The CRA presumes five years unless the expected product lifetime is shorter. Which released versions do we currently support? | Determines the SBOM retention obligation and what we tell reporters. | `SECURITY.md`, `cybersecurity-policy.md` §6.1 |
| 3 | **Policy owner and approval.** Who inside OPC Federation AISBL owns the cybersecurity policy, and how is it approved? | Article 24(1) requires the policy to be documented "in a verifiable manner"; an unapproved draft is weak evidence. | `cybersecurity-policy.md` header |
| 4 | ~~**CVE assignment route**~~ — **RESOLVED: both, in sequence.** The OPC Foundation is **GCVE Numbering Authority 105** and assigns `GCVE-105-<YEAR>-<NNNN>` as the primary identifier, because it is the only one obtainable in a reasonable timeframe. Not being a CNA, it then requests a CVE from another CNA (e.g. GitHub) as a secondary identifier, which is often significantly delayed; the advisory is reissued when it arrives. Advisories are signed CSAF v2.0. See [`cve-policy.md`](cve-policy.md). | — | `cybersecurity-policy.md` §4.4, `cve-policy.md` |
| 5 | **Coordinating CSIRT confirmation.** I have assumed CCB / CERT.be, on the basis that OPC Federation AISBL is a Belgian AISBL. Please confirm the main establishment. | Choosing the wrong coordinator CSIRT can invalidate a notification. | `reporting-runbook.md` §0.2, §5 |
| 6 | **Named reporters** — primary and backup Assigned Representatives, the person authorised to file outside working hours, and legal counsel contact. | Article 14's 24-hour clock is not survivable without named individuals agreed in advance. EU Login accounts are personal and MFA-bound; they cannot be created during an incident. | `reporting-runbook.md` §0 |
| 7 | **Downstream integrator list** — do vendors ship the LDS inside their own products, and do we have contacts for embargo pre-notification? | They inherit obligations from what we publish; §5 of the policy commits us to pre-notify them. | `cybersecurity-policy.md` §5 |
| 8 | **Whether CI returns.** The GitHub Action was removed in `b88952d`, so builds are local-only. | SBOM generation, CVE monitoring, and release tagging all want automation. If CI is coming back I would move the SBOM step and add dependency monitoring there. | gap 7 |

## Engineering work still open

Tracked with planned actions in [`cybersecurity-policy.md`](cybersecurity-policy.md) §7.

Priority follows **remote reachability**, not scanner volume. The exposure
mapping in `cybersecurity-policy.md` §1.1 is what separates the two: our two
network-facing components are `opcualds.exe` and `mDNSResponder.exe`, and
everything an unauthenticated attacker can touch runs through them.

**P1 — remote attack surface and Article 14 readiness**

1. **mDNSResponder CVE delta assessment** (gap 2). A **network-facing** listener
   forked from Apple 576.30.4, roughly a decade behind upstream, with no
   assessment on record. This is the largest unquantified risk in the product.
   The assessment itself is cheap — enumerate CVEs against upstream since
   576.30.4 and check reachability in the fork — and it is what tells you
   whether the expensive remediation is needed at all. Do this first because
   you currently cannot answer the question, not because the answer is known
   to be bad.
2. **Tag releases and record submodule SHAs** (gap 3). Without this we cannot
   state which versions are affected inside 72 hours. The SBOM generator now
   captures submodule commits at build time, which covers releases from here
   on; historical releases remain unmapped.

**Done**

- ~~**Replace `Opc.Ua.CertificateGenerator.exe`'s end-of-life OpenSSL**~~
  (gap 1) — **resolved 2026-10-05.** Rewritten in C as the in-tree
  `CertificateGenerator/` project (v2.1.342.10), linking the same OpenSSL 3.5.7
  as the LDS. The Misc-Tools submodule is removed and there is no second
  OpenSSL in the build. Note it does **not** settle the Annex III Class I
  question — see the residual-risk section above.

**P3/P4 — hardening and hygiene**

3. **Restore CI** (gap 7), then automate SBOM generation and dependency
   monitoring.
4. **Finish the certificate generator port** (gap 9): five commands and the
   Windows-store paths still report `BadNotSupported`. A functional gap rather
   than a security one, but anyone who needs those commands has to keep a 1.x
   binary around, and that one does carry the old OpenSSL.
5. **Assess ECC SecurityPolicy support in the LDS itself** (gap 10). The
   certificate generator now issues certificates for every OPC UA ECC policy,
   but the vendored stack 1.04.342 cannot negotiate them — so the certificates
   can be created but not yet used by `opcualds.exe`.
6. OpenSSL 3.x API migration in `LDS/stack` and removal of `/wd4996` (gap 4);
   decide on `/Qspectre` as default (gap 6); correct the mDNSResponder license
   attribution upstream (gap 8).

## References

- [Regulation (EU) 2024/2847 full text](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [Commission CRA summary](https://digital-strategy.ec.europa.eu/en/policies/cra-summary) · [reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
- [ENISA Single Reporting Platform](https://portal.cra-srp.enisa.europa.eu/) · [FAQ](https://www.enisa.europa.eu/cra-srp)
- [ORC WG — Open Source Software Stewards and the CRA](https://orcwg.org/files/cra/resources/white-paper-on-open-source-software-stewards-and-cra.pdf)
- [Red Hat — CRA stewardship guidelines](https://access.redhat.com/security/eu-cyber-resilience-act-stewardship-guidelines)
- BSI TR-03183-2 — SBOM technical requirements
