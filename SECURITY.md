# Security Policy

The OPC UA Local Discovery Server (LDS) is published as free and open-source software under the MIT License by OPC Federation AISBL, acting as an
**open-source software steward** within the meaning of Article 24 of Regulation (EU) 2024/2847 (the Cyber Resilience Act, "CRA").

This document is the public entry point for reporting security problems. The full policy it implements is in [`docs/cra/cybersecurity-policy.md`](docs/cra/cybersecurity-policy.md).

## Reporting a vulnerability

Any vulnerabilities or security concerns should be reported by:

1) Submitting a [private report](https://github.com/OPCFoundation/OPC-SecurityAdvisories/security) to GitHub;
2) Email to ‘securityteam AT opcfoundation DOT org’. 

A PGP key to encrypt any sensitive security report can be found [here](https://opcfoundation.org/SecurityBulletins/securityteam_public_key.txt). 

Please include, as far as you are able:

- The affected component (`opcualds.exe`, `mDNSResponder.exe`, `dnssd.dll`,  `ldsca.dll`, the MSI itself, or a bundled third-party library)
- The product version — run `opcualds.exe -v`, or take the version from Add/Remove Programs
- Platform and architecture (Windows version, x86 or x64)
- Reproduction steps, a proof of concept, or a crash dump
- Your assessment of impact, and whether you believe the issue is being  exploited in the wild

If you have evidence that the issue is **already being exploited**, say so prominently in your first message. That changes our legal reporting deadlines under CRA Article 14 from "when triaged" to **within 24 hours**, so we need to know immediately.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | 3 working days |
| Initial triage and severity assessment | 10 working days |
| Status update cadence while open | Every 30 days |
| Fix or documented mitigation, high/critical | 90 days from triage |
| Fix or documented mitigation, medium/low | Next scheduled release |

These are good-faith targets for a volunteer-supported open-source project, not a contractual service level. Where a fix depends on an upstream project (see *Third-party components* below), our target is to report upstream promptly and track their fix, not to fork.

## Coordinated disclosure

We ask for **90 days** from acknowledgement before public disclosure, or until a fix ships. We will:

- Agree a disclosure date with you rather than impose one
- Credit you in the advisory unless you ask us not to
- Tell you if we need longer, and why
- Publish an advisory even where we decide not to fix, explaining why

We support embargoed pre-notification to downstream redistributors who ship the LDS inside their own products. If that is you, see [`docs/cra/cybersecurity-policy.md`](docs/cra/cybersecurity-policy.md) for how to join the notification list.

We are a non-profit that provides standards and open source software to the OT community and do not operate a paid bug bounty.

## Identifiers — GCVE with optional secondary CVE.

The OPC Foundation is [GCVE Numbering Authority 105](https://gcve.eu/gna/105/) and assigns identifiers of the form `GCVE-105-<YEAR>-<NNNN>`.

The OPC Foundation will request a CVE from another CNA (for example GitHub, for code hosted there) as a secondary identifier. That request is often significantly delayed, so:

- advisories may be published with only a GCVE;
- when CVE is added when issued, the advisory is reissued with both;

Where an upstream CVE affects a component we ship, such as OpenSSL, the advisory references that CVE instead of minting a new identifier. GCVE is interoperable rather than parallel: namespace 0 is reserved for the CVE program, so `CVE-2023-40224` is also `GCVE-0-2023-40224`. 

Advisories are published as signed CSAF v2.0 documents at [opcfoundation.org/security/csaf](https://opcfoundation.org/security/csaf).

Full policy, including what does and does not earn an identifier and how this differs from CRA Article 14 reporting: [`docs/cra/cve-policy.md`](docs/cra/cve-policy.md).

## Scope

**In scope**: this repository, which assembles and packages the installer:

- The build pipeline (`build.ps1`), hardening flags (`cmake/Hardening.cmake`), and the WiX installer and merge module (`WiX/`)
- The MSI custom actions (`CustomActions/` → `ldsca.dll`)
- Insecure defaults in the shipped `ualds.ini` or the PKI store layout theinstaller provisions
- The integrity of released artifacts and their code signatures

**Report here, but fixed upstream**: the LDS is assembled from submodules that are separate projects:

| Submodule | Repo |
|---|---|
| `LDS/` | [OPCFoundation/UA-LDS](https://github.com/OPCFoundation/UA-LDS) |
| `mDNSResponder/` | [OPCFoundation/UA-LDS-mDNSResponder](https://github.com/OPCFoundation/UA-LDS-mDNSResponder) |


**Out of scope:**

- Vulnerabilities in OpenSSL, the Apple mDNSResponder upstream, or the Microsoft Visual C++ runtime as such. Report those to their maintainers. Do
  tell us if the LDS is affected and we have not yet shipped the update  part is ours.
- The OPC UA specification itself. Those go to the OPC Foundation specification process.
- Findings from an automated scanner with no demonstrated impact on the LDS as shipped, including reports that a bundled library version "appears in a CVE database" without analysis of whether the affected code path is reachable in our build. Our builds use `no-shared no-asm no-autoload-config`, so some of OpenSSL is not compiled in at all.
- Denial of service achieved only through resource exhaustion by an already privileged local user.

## Attack surface

So that reports arrive with calibrated severity, here is what is actually exposed:

| Component | Exposure |
|---|---|
| `opcualds.exe` | **Network-facing.** The discovery service. Accepts OPC UA requests; runs as a Windows service. The primary attack surface. |
| `mDNSResponder.exe` | **Network-facing.** Listens for and emits mDNS/DNS-SD traffic on the local network segment. |
| `dnssd.dll` | Local API surface, consumed in-process by `opcualds.exe`; handles data that originated on the network. |
| `ldsca.dll` | Install-time only. Runs inside the MSI custom-action context, which is already elevated. |
| `Opc.Ua.CertificateGenerator.exe` | **Not network-facing.** Local command-line utility, invoked manually or by a local program that already holds the necessary rights. No socket, no service account, not used by the discovery service at runtime. |

Findings against the two network-facing components are the ones most likely to be severe. For the rest, please include in your report how an attacker reaches the code, not only that the code is reachable in principle.

## Supported versions

Version 1.04.x (Current LTS)

## Software Bill of Materials

A CycloneDX 1.6 SBOM is generated at build time and shipped in the release ZIP alongside the MSI. See [`sbom/README.md`](sbom/README.md).

## Our own reporting obligations

As an open-source software steward, OPC Federation AISBL will be required under CRA Article 24(3) — from 11 December 2027 — to report actively exploited vulnerabilities in this product, and severe incidents affecting the infrastructure we provide for its development, to ENISA and our coordinating CSIRT.

We operate that process now rather than waiting for the date. If you report something with evidence of active exploitation, treat it as triggering a regulatory notification on a 24-hour clock.

Note what is **not** reportable, so that nothing discourages you from filing: the obligation is triggered by *active exploitation*, not by the existence of a vulnerability or a CVE. A vulnerability you report to us that is not being exploited in the wild creates no notification duty — it is handled through ordinary vulnerability handling, on the timelines above.

Those notifications identify the product and the nature of the flaw. They do not identify you as the reporter unless you ask us to credit you publicly.
