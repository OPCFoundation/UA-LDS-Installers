# Cybersecurity Policy — OPC UA Local Discovery Server

**Entity:** OPC Federation AISBL
**CRA role:** Open-source software steward, Regulation (EU) 2024/2847 Article 24
**Product:** OPC UA Local Discovery Server (`UA-LDS-Installers` and its submodules)
**Document status:** `<<TBD: approval — see README.md, open item 3>>`
**Version:** 1.0 (draft)
**Last reviewed:** 2026-10-04
**Review cadence:** Annually, and on any change to the shipped component set

---

## 0. Why this document exists

CRA Article 24(1) requires an open-source software steward to "put in place and
document **in a verifiable manner** a cybersecurity policy to foster the
development of a secure product with digital elements as well as an effective
handling of vulnerabilities by the developers of that product."

"In a verifiable manner" is why this document lives in the product repository
under version control rather than on a website: its history, authorship, and
effective date are independently checkable, and it is distributed with the
source it governs.

Article 24(2) requires us to supply this document to a market surveillance
authority on reasoned request, in a language they readily understand. This
document is maintained in English for that purpose.

### Obligation map

Each Article 24(1) element and where it is satisfied:

| Requirement | Section |
|---|---|
| Foster development of a secure product | §2, §3 |
| Effective handling of vulnerabilities by developers | §4 |
| Foster voluntary vulnerability reporting (Art. 15) | §4.1, and `/SECURITY.md` |
| Documenting, addressing and remediating vulnerabilities | §4.2–§4.4 |
| Promote information sharing within the open-source community | §5 |
| Account for the steward's specific nature and arrangements | §1, §6 |

Article 24(3) reporting duties are operationalised separately in
[`reporting-runbook.md`](reporting-runbook.md).

---

## 1. Scope and the nature of this stewardship

OPC Federation AISBL does not sell the LDS, does not license it commercially,
and does not provide it under contract or with a warranty. It is published
under the MIT License for use by the OPC UA community, including in commercial
products built by third parties.

Our role is custodial: we maintain the repositories, review and merge
contributions, operate the build and signing infrastructure, and publish
releases. We do not control how downstream integrators configure, deploy, or
redistribute the software.

**This policy therefore commits us to process, not to outcomes in the field.**
Where an obligation depends on a party we do not control — an upstream project,
a downstream integrator, a deployment operator — this policy states what we
will do, and names the boundary.

### Covered repositories

| Repository | Role |
|---|---|
| `UA-LDS-Installers` (this repo) | Build orchestration, installer, packaging |
| `UA-LDS` | `opcualds.exe`, `dnssd.dll`, vendored OPC UA ANSI C stack |
| `UA-LDS-mDNSResponder` | `mDNSResponder.exe` (fork of Apple mDNSResponder) |

### 1.1 Attack surface of shipped components

Severity assessment starts here. A CVE list tells you a component contains a
flaw; it does not tell you whether anyone can reach it. Recording exposure once,
in one place, keeps that judgement consistent across triage decisions and
prevents each assessment from re-deriving the threat model.

| Component | Exposure | Reachable by |
|---|---|---|
| `opcualds.exe` | **Network-facing** | Any host that can reach the LDS port. Runs as a Windows service. The primary attack surface. |
| `mDNSResponder.exe` | **Network-facing** | Any host on the local network segment, via mDNS/DNS-SD |
| OPC UA ANSI C stack | Network-reachable | In-process in `opcualds.exe`; parses network-origin messages |
| OpenSSL 3.5.7 | Network-reachable | Crypto and PKI for the network-facing service |
| `dnssd.dll` | Network-reachable | In-process; handles data originating on the network |
| MSVC CRT (static) | Network-reachable | Linked into every binary, including both network-facing ones |
| `ldsca.dll` | Install-time | MSI custom-action context only, already elevated |
| `Opc.Ua.CertificateGenerator.exe` | **Local only** | A command-line utility. No listening socket, no service account, not used by the discovery service at runtime. Runnable only by a program already executing on the machine with the necessary rights. |

Consequences that follow, and that should not have to be re-argued each time:

- Advisories against the two **network-facing** components, and against the
  stack, OpenSSL 3.x, and the CRT behind them, are the ones that can be
  remotely triggered. These get priority.
- The certificate generator's **local-only** exposure bounds the severity of
  anything found in it: reaching its code presupposes local execution with
  sufficient privilege, at which point it is not an attacker's most direct
  route to anything. That reasoning is recorded as the `cra:exposure` property
  in each SBOM so it travels with the inventory, rather than being reconstructed
  under time pressure during an Article 14 assessment.

This mapping is maintained as the `exposure` field in each project's own SBOM
manifest — the project that ships a component is the one that knows how it is
reached — and published in every SBOM as the `cra:exposure` property.

### Boundary of responsibility

Out of scope for remediation by us, in scope for routing and disclosure:
OpenSSL, Apple's upstream mDNSResponder, the Microsoft Visual C++ runtime, the
Windows platform, the OPC UA specification, and any downstream product that
embeds the LDS.

---

## 2. Secure development

### 2.1 Build integrity

- Releases are built by `build.ps1`, which is version-controlled and reviewed
  as code. Build configuration is not held outside the repository.
- All third-party source is pinned: OpenSSL by upstream git tag
  (`openssl-3.5.7`), and each submodule by commit. No release depends on a
  floating branch or a mutable download.
- Shipped binaries and the MSI are Authenticode-signed with an RFC 3161
  timestamp via Azure Key Vault. Signing credentials are held as environment
  secrets, never in the repository.
- Every release records the exact commit of this repository and of each
  submodule. See §6.2 — this is what makes "which versions are affected?"
  answerable within the Article 14 deadlines.

### 2.2 Exploit mitigations

`cmake/Hardening.cmake` applies, for every compiled artifact:

| Flag | Mitigation |
|---|---|
| `/GS` | Stack buffer overrun detection |
| `/sdl` | Additional SDL checks — pointer overwrite, format string |
| `/guard:cf`, `/GUARD:CF` | Control Flow Guard, compiler and linker |
| `/NXCOMPAT` | Data Execution Prevention |
| `/DYNAMICBASE` | Address Space Layout Randomisation |
| `/SAFESEH` (x86) | Safe exception handlers |
| `/HIGHENTROPYVA` (x64) | 64-bit ASLR entropy |

Any change that weakens this set requires a recorded rationale in the pull
request. Two suppressions are currently in force and are tracked as debt in
§7: `/wd4996` and the absence of `/Qspectre` by default.

### 2.3 Secure defaults

The installer provisions the configuration and PKI store layout that a fresh
deployment starts from. Changes to shipped defaults in `ualds.ini`, the PKI
directory structure, or the `ldsca.dll` custom actions that initialise them are
treated as security-relevant and reviewed on that basis — a default is a
security decision made on behalf of every operator who never revisits it.

### 2.4 Contributions

- Changes reach `master` by pull request; direct pushes are reserved for
  release mechanics.
- A contribution that adds a third-party component, changes a pinned version,
  alters a hardening flag, touches certificate or key handling, or changes a
  shipped default must say so in the pull request description.
- Adding or bumping a third-party component requires the SBOM manifest
  of whichever project owns the component to be updated in the same pull
  request — `LDS/sbom/components.json` for the service, its own manifest for
  mDNSResponder, `sbom/components.json` for installer-owned pieces. An
  unrecorded dependency is the failure mode this policy exists to prevent.
- Per CRA Recital 18, individual contributors who are not responsible for the
  product bear no obligations under this policy.

---

## 3. Dependency and component management

### 3.1 Inventory

**Each project owns its own inventory.** `LDS/sbom/components.json`,
`mDNSResponder/sbom/components.json` and `sbom/components.json` each declare
only what their own repository produces and links; the installer's manifest
composes the others in at build time. Each repository is a public project that
publishes its own SBOM, and a component declared in two places is a component
that will eventually disagree with itself.

Taken together they are the authoritative inventory of everything we ship. It
is rendered into a CycloneDX 1.6 SBOM per architecture at build time and
published with each release.

The inventory is hand-curated rather than scanner-generated, deliberately. Every
third-party component here is vendored C source or a pinned upstream git tag;
there is no package manifest for a scanner to read, and automated tooling
produces a near-empty SBOM for this build. A curated manifest that is actually
correct is worth more than a generated one that silently omits OpenSSL.

We record **transitive as well as top-level** dependencies. Annex I Part II(1)
requires only top-level, but the components that carry our real risk — OpenSSL,
the vendored OPC UA stack, the static C runtime — sit below the top level.

### 3.2 Monitoring

- Each inventory entry carries a PURL and, where one exists, a CPE, so that
  published advisories can be matched mechanically.
- Components without a usable CPE (the OPC UA ANSI C stack, our mDNSResponder
  fork) cannot be monitored by CVE feed and are reviewed manually against
  upstream release notes. These are flagged `"cveMonitoring": "manual"` in the
  manifest.
- Statically linked components deserve explicit attention: the MSVC C runtime
  is linked with `/MT`, so a runtime vulnerability is **not** fixed by Windows
  Update on the operator's machine. It requires us to rebuild and re-release.
  The same applies to OpenSSL, which is built `no-shared`.

### 3.3 Update policy

| Trigger | Response |
|---|---|
| Known-exploited vulnerability in a shipped component | Rebuild and release as the top priority |
| Critical or high severity, reachable in our build | Rebuild and release within 30 days |
| Component reaches end-of-life upstream | Plan migration before EOL; record in §7 if we cannot |
| Routine upstream release | Adopt at the next scheduled release |

"Reachable in our build" is a judgement we must make and record, not assume. It
has two independent dimensions, and both must be answered:

1. **Is the vulnerable code compiled in at all?** OpenSSL is configured
   `no-shared no-asm no-autoload-config`, so some advisories do not apply to the
   code we actually build. Note this list shrank when `no-ec` was removed to
   support the OPC UA ECC policies — elliptic-curve advisories now **do** apply.
2. **Can an attacker reach it if it is?** See the exposure mapping in §1.1. A
   flaw in a local-only command-line utility and the same flaw in a
   network-facing service are not the same finding.

Where we decide an advisory is not applicable, the reasoning is written into the
advisory record — an unexplained "not affected" is indistinguishable from an
oversight.

---

## 4. Vulnerability handling

### 4.1 Intake (fosters voluntary reporting — Article 15)

`/SECURITY.md` is the public entry point. It provides a private channel
separate from the public issue tracker, states response targets, defines
scope, and commits to credit. We will not pursue anyone who reports in good
faith within that scope.

### 4.2 Triage and documentation

Every report, including those we reject, gets a record containing: date of
receipt, reporter and preferred attribution, affected components and versions,
a severity assessment with its reasoning, reachability analysis in our build
configuration, the remediation decision, and the disclosure timeline.

Severity uses CVSS v4.0, scored against a default installation as the installer
provisions it, with attack vector taken from the component's exposure in §1.1.
Where our score differs materially from an upstream score, we record why — a
component we ship local-only may legitimately score below its upstream rating,
and that divergence needs its reasoning on the record rather than looking like
a downgrade of convenience.

**The triage record must state explicitly whether there is evidence of active
exploitation**, because that single determination starts the Article 14
24-hour clock. If the answer is unclear, treat it as the runbook's §2
"uncertain" path and consult rather than let the clock run.

### 4.3 Remediation

- Fixes are developed in private until disclosure where the issue is not
  already public.
- A security fix ships as a release with a version bump, never as a
  replacement binary under an existing version number.
- Where we will not fix — unmaintained component, disproportionate effort,
  disputed impact — we document the decision and publish a mitigation or
  workaround instead. Silence is not an outcome.
- Fixes belonging upstream are reported upstream, tracked, and adopted. We fork
  only if upstream is unresponsive and the issue is serious, and we record that
  decision.

### 4.4 Advisories

Published for every confirmed vulnerability, at disclosure, stating: affected
and fixed versions, severity and vector, impact, workarounds, and credit.

Advisories use the existing OPC Foundation programme rather than anything
invented for this product: signed **CSAF v2.0** documents published to
[opcfoundation.org/security/csaf](https://opcfoundation.org/security/csaf),
assessed by the OPC UA Security Working Group using CVSS.

**GCVE is the primary identifier; a CVE is requested as a secondary one.** The
OPC Foundation is GCVE Numbering Authority 105 and assigns
`GCVE-105-<YEAR>-<NNNN>` on confirming a vulnerability — it is the only
identifier obtainable in a timeframe that disclosure can work to. Not being a
CNA, the Foundation then requests a CVE from another CNA; that typically arrives
well after publication, at which point the advisory is reissued carrying both.
Where an upstream CVE already covers a component we ship, the advisory
references it instead of minting a new identifier.

An advisory is never withheld for want of a CVE, and the Article 14 clock never
waits for one. The full policy — what earns an identifier, how third-party
components are handled, and why this is distinct from Article 14 reporting — is
in [`cve-policy.md`](cve-policy.md).

Reports reach the OPC Foundation security team at
`securityteam@opcfoundation.org`; the machine-readable contact record is
`/.well-known/security.txt` (RFC 9116).

---

## 5. Information sharing with the open-source community

Article 24(1) requires us to promote the sharing of information about
discovered vulnerabilities within the open-source community. In practice:

- **Upstream first.** A vulnerability we find in a dependency is reported to
  that project under its own disclosure policy, with our analysis and, where we
  have one, a patch.
- **Downstream pre-notification.** Integrators who ship the LDS inside their
  own products may join an embargo notification list, receiving advance notice
  under embargo so their own CRA obligations are not sprung on them at
  publication. Downstream vendors inherit real obligations from what we ship;
  giving them no warning would make our compliance their incident.
  Request access via the `/SECURITY.md` contact.
- **Fork transparency.** Our mDNSResponder fork diverges from Apple's upstream.
  Where we fix something that also affects upstream, we say so publicly even
  though upstream may not act, so that others carrying the same fork can
  assess themselves.
- **Full advisories.** We publish enough technical detail for downstream
  consumers to assess their own exposure, after the embargo period.

---

## 6. Records, retention, and traceability

### 6.1 What we keep

| Record | Retention |
|---|---|
| Vulnerability reports and triage records | Support period + 5 years |
| Published advisories | Indefinitely |
| SBOMs, per release | Support period + 5 years |
| Article 14 notifications and correspondence | 10 years |
| Release manifests (§6.2) | Indefinitely |

CRA Annex I Part II(1) requires the SBOM to be kept up to date **for the
support period**, not merely produced once at release.

### 6.2 Release traceability

Every release must be reconstructible and attributable, because Article 14
notifications require us to state which versions are affected within 72 hours.
For each release we record:

- An annotated, signed git tag on this repository
- The commit SHA of each submodule as built
- The pinned OpenSSL tags and the MSVC toolset version
- The generated SBOMs
- SHA-256 digests of the published MSI and ZIP

**Current gap:** this repository has no tags at all, so released versions
cannot presently be mapped back to source state. Closing this is tracked in §7
and is a prerequisite for meeting the 72-hour deadline with accurate
information.

---

## 7. Known gaps and accepted debt

Recorded openly, because an undocumented known weakness is worse than a
documented one. Each item needs an owner and a target date — see
[`README.md`](README.md).

Gap numbers are **stable identifiers** and are referenced from
`sbom/components.json`, `/SECURITY.md`, and `README.md`. Do not renumber them
when priorities change — change the priority column instead.

| # | Gap | Pri | Risk | Planned action |
|---|---|---|---|---|
| 1 | ~~`Opc.Ua.CertificateGenerator.exe` built against **OpenSSL 1.1.1w** (EOL 2023-09-11, unpatched CVEs)~~ | **RESOLVED** 2026-10-05 | — | Rewritten in C as the in-tree `CertificateGenerator/` project (v2.1.342.10) against the same OpenSSL 3.5.7 as the LDS. The Misc-Tools submodule and the OpenSSL 1.1.1w build path are both gone. The CLI is preserved; `CertificateGenerator/README.md` lists the deviations. Five commands (`convert`/`password`, `request`, `process`, `revoke`/`unrevoke`, `replace`) and the Windows-store paths are not yet ported and report `BadNotSupported` — tracked as gap 9 |
| 2 | `mDNSResponder` forked from Apple **576.30.4** (c. 2015) | **P1** | **Highest unquantified risk in the product.** A network-facing listener roughly a decade behind upstream, with no assessment on record | CVE delta assessment against current upstream; then rebase, backport, or document non-applicability |
| 3 | No git tags; no release manifest | **P1** | Cannot answer "which versions are affected" within 72 h | Tag retrospectively where determinable; tag every release from now on |
| 4 | `/wd4996` suppresses deprecation warnings in `cmake/Hardening.cmake` | P4 | Masks deprecated OpenSSL 3.x API use in `LDS/stack`; hides future signal | Migrate `LDS/stack` to OpenSSL 3.x `EVP_PKEY` interfaces, then remove the suppression |
| 5 | ~~OpenSSL built `no-ec` (`build.ps1`)~~ | **RESOLVED** 2026-10-05 | — | `no-ec` removed from the OpenSSL `Configure` line. All seven certificate-generator `-keyType` values now work, covering every OPC UA ECC SecurityPolicy (`ECC_nistP256`, `ECC_nistP384`, `ECC_brainpoolP256r1`, `ECC_brainpoolP384r1`, `ECC_curve25519`, `ECC_curve448`). **Widens the advisory surface**: EC, ECDH, ECDSA and ECX code is now compiled in, so elliptic-curve advisories apply where they previously did not — see §3.3. Separately, this does not mean the LDS can *negotiate* ECC policies; the vendored stack 1.04.342 predates them (gap 10) |
| 6 | `/Qspectre` is opt-in, not default | P4 | Speculative-execution exposure | Decide whether to make it default; record the decision either way |
| 7 | No CI; builds are local-only (GitHub Action removed in `b88952d`) | P3 | No automated SBOM generation, CVE monitoring, or reproducibility check | Restore CI and run SBOM generation and dependency monitoring there |
| 8 | `mDNSResponder/LICENSE.md` asserts MIT/OPC Federation over Apache-2.0 upstream code | P4 | Inaccurate provenance; propagates into downstream SBOMs | Correct upstream in the `UA-LDS-mDNSResponder` repository. Our SBOM already records Apache-2.0 |
| 9 | Five `Opc.Ua.CertificateGenerator.exe` commands and the Windows-store paths are not ported to the OpenSSL 3.x rewrite | P3 | Functional regression, not a security gap: the unported commands report `BadNotSupported` rather than failing silently or appearing to succeed. Users needing them must keep a copy of the 1.x tool, which does carry the end-of-life OpenSSL | Port in order: `convert`/`password`, `request`/`process`, `revoke`/`unrevoke`, `replace`, then the Windows certificate store paths. Build a differential harness against the 1.x binary to prove parity |
| 10 | The LDS cannot negotiate the OPC UA ECC SecurityPolicies | P3 | Not a vulnerability, a capability gap. The certificate generator now issues ECC certificates for every ECC policy, but `opcualds.exe` uses the vendored OPC UA ANSI C stack 1.04.342, which predates them — so ECC certificates can be created and distributed but not used by the LDS itself | Assess what stack work ECC policy support needs. Related to gap 4: the stack also still uses deprecated OpenSSL 3.x APIs |

**P1** is where the remote attack surface and the Article 14 response capability
are.

Note how gap 1 resolved. It was held at P2 on the strength of the §1.1 exposure
mapping — local-only reachability, so scanner noise rather than remote risk —
and was then closed by work done for other reasons (removing a second OpenSSL
from the build, and the Annex III classification question). The exposure
mapping was what stopped it being treated as an emergency in the meantime.
That is the mapping doing its job, and the reason it is written down.

---

## 8. Cooperation with authorities

Under Article 24(2) we will cooperate with market surveillance authorities on
request to mitigate cybersecurity risks in the LDS, and will provide this
policy and supporting documentation on reasoned request, in English, in
electronic form.

Our coordinating CSIRT and point of contact are identified in
[`reporting-runbook.md`](reporting-runbook.md).
