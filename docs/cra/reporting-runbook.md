# CRA Article 14 Reporting Runbook

**Status: binding on us from 11 December 2027. Operationally ready before then.**

The date depends on our role, and the two must not be confused:

- **Article 14 itself** has applied since **11 September 2026**. By its own
  terms it binds *manufacturers* ("a manufacturer shall notify…").
- A **steward** is defined as a legal person *other than* a manufacturer, so
  Article 14 does not reach us directly. The provision that extends it to
  stewards is **Article 24(3)** — and Article 24 is neither Article 14 nor
  within Chapter IV, so under **Article 71(2)** it applies from the general
  date, **11 December 2027**.

**Why we operate this runbook now anyway.** Three reasons, in order of weight:

1. **The steward determination is not certified.** It rests on the analysis in
   [`README.md`](README.md), which records the residual risk — chiefly that we
   distribute a signed pre-compiled MSI rather than source alone. If that
   determination were ever rejected, we would be a manufacturer, and the
   manufacturer deadline is **not** 2027: Article 14 has been live since
   11 September 2026. **The role risk and the date risk are the same risk.**
   Being ready costs little; being wrong about both at once would be
   unrecoverable.
2. **Article 15 voluntary reporting is available to anyone, now.** If we find
   an actively exploited vulnerability before December 2027, we intend to
   report it. The community that depends on this software is not served by
   waiting for a compliance date.
3. Capability cannot be built during a 24-hour window. See §0.

**Scope note.** The Commission has confirmed there is no obligation to
retrospectively report active exploitation already known before a party's
obligation starts.

**Interpretive caveat.** The Article 24(3) → Article 71(2) chain above is a
reading of the text, not a Commission holding. The Commission issued guidance
addressing open source in more detail on 27 July 2026; confirm against that
document and with counsel before relying on the later date to *defer* anything.
Nothing in this runbook depends on which date is correct — it is written to be
operable either way, which is the point.

---

## 0. Before an incident — one-time setup

Do this now. The 24-hour clock is not survivable if the first step is creating
an account.

| # | Action | Owner | Status |
|---|---|---|---|
| 1 | Create EU Login accounts with MFA for the primary and at least one backup reporter | `<<TBD>>` | Not started |
| 2 | Decide the Primary Assigned Representative and backups (see §0.1) | `<<TBD>>` | Not started |
| 3 | Confirm the coordinating CSIRT (see §0.2) | `<<TBD>>` | Not started |
| 4 | Record the security contact in `/SECURITY.md` and route it to a monitored inbox with a named backup | `<<TBD>>` | Not started |
| 5 | Confirm who may authorise a notification outside working hours (see §0.3) | `<<TBD>>` | Not started |
| 6 | Dry-run this runbook against a fictional report | `<<TBD>>` | Not started |

### 0.1 EU Login and Assigned Representatives

The ENISA Single Reporting Platform is at
**https://portal.cra-srp.enisa.europa.eu/** and authenticates through EU Login.

Mechanics that matter for planning:

- EU Login accounts are **personal and require MFA**. There is no shared
  organisational login. Every reporter is a named individual.
- An organisation has one **Primary Assigned Representative** and up to 20
  secondaries. The coordinating CSIRT validates the association between a
  representative and the organisation.
- A representative whose association is still pending validation may file **up
  to 20 notifications** before validation becomes mandatory — so a pending
  association does not block an urgent first report.
- ENISA has asked organisations to initiate the AR validation process only when
  they actually need to notify, to limit CSIRT validation workload.

**Recommended split given that guidance:** create the EU Login accounts and
agree who the representatives are now, because that is the part that takes
human time and cannot be done at 02:00. Defer the AR association and CSIRT
validation until a notification is actually needed, as ENISA prefers. Nominate
at least two people — a single named reporter on holiday is a missed deadline.

There is currently **no API** for the SRP. Submission is manual through the web
portal. Do not design a process that assumes automation.

### 0.2 Coordinating CSIRT

The notification is addressed to the CSIRT of the Member State where we have
our main establishment. OPC Federation AISBL is a Belgian AISBL, which points
to the **Centre for Cybersecurity Belgium (CCB / CERT.be)**.

**Verify this before relying on it.** Picking the wrong coordinator CSIRT can
invalidate a notification. Confirmation is open item 5 in
[`README.md`](README.md).

We report **once** through the SRP. ENISA receives it simultaneously, and the
coordinating CSIRT forwards it to other Member States' CSIRTs where the product
has been made available. Do not file separately with national authorities.
National CSIRT email is not a substitute for the platform.

### 0.3 Decision authority

A 24-hour deadline cannot wait for a committee. One named person must be able
to authorise a notification alone, with a second as backup. An over-report is
recoverable; a missed deadline is not.

---

## 1. What we must report

Article 24(3) applies Article 14 to stewards in two narrowed ways. These are
different triggers with different subject matter, and conflating them is the
easiest way to get this wrong.

### Trigger A — Actively exploited vulnerability in the LDS
*Article 14(1), applicable to the extent we are involved in developing the product.*

An **actively exploited vulnerability** (Art. 3(42)) is one where there is
reliable evidence that a malicious actor has exploited it in a system without
the owner's permission.

| Is it reportable? | |
|---|---|
| Vulnerability we found and fixed ourselves, no exploitation | **No** — ordinary vulnerability handling |
| Externally reported, no evidence of exploitation | **No** — ordinary handling |
| Reliable evidence of exploitation in the wild | **Yes** |
| Proof-of-concept published, no observed exploitation | **No**, but monitor closely — this often precedes exploitation |
| Exploited in a bundled third-party component, reachable as we ship it | **Yes** — our product is affected |
| Exploited in a component we ship but which is not reachable in our build configuration | Assess and **record the reasoning**; if not reachable, not reportable |

### Trigger B — Severe incident affecting our development infrastructure
*Article 14(3) and 14(8), applicable to the extent a severe incident affecting the security of the product affects the network and information systems we provide for its development.*

This covers **our infrastructure**, not operators' deployments. Concretely:

- Compromise of the OPC Foundation GitHub organisation or these repositories
- Compromise or misuse of the **Azure Key Vault code-signing credentials** —
  a signed malicious artifact is the most severe realistic scenario here
- Compromise of the build environment that produces releases
- Unauthorised modification of a published release artifact

An operator's LDS being breached through their own misconfiguration is not our
reportable incident. Our signing key being used to sign something we did not
build is.

### Not reportable
Vulnerabilities in a third-party component that are not reachable in the LDS as
shipped; incidents confined to a downstream product that embeds the LDS, where
our code is not implicated; routine security patching.

---

## 2. The 24 / 72 / 14 cascade

**The clock starts when we become aware** — not when we finish triage, not when
we confirm a fix, not when we agree internally. Awareness means a credible
report has reached someone responsible.

Where the facts are uncertain, **file the early warning and refine later.** The
early warning is explicitly allowed to be thin, and later stages may be skipped
if earlier ones already carried the information. Lateness cannot be corrected;
incompleteness can.

### Stage 1 — Early warning: within 24 hours

Required content is minimal: that we are aware of an actively exploited
vulnerability or severe incident, and where applicable the Member States where
we are aware the product has been made available.

For the LDS, availability is effectively EU-wide — it is published for public
download, not distributed through a controlled channel. Say so rather than
attempting a list we cannot substantiate.

### Stage 2 — Notification: within 72 hours

Add, to the extent available: general information about the product; the
general nature of the exploit and of the vulnerability; corrective or
mitigating measures we have taken; measures users can take; and how sensitive
we consider the information to be.

This is where release traceability is load-bearing. "Which versions are
affected" needs to be answerable from release tags and recorded submodule SHAs
— see `cybersecurity-policy.md` §6.2, and note that this capability does not
exist yet (gap 3).

### Stage 3 — Final report

| Trigger | Deadline |
|---|---|
| Actively exploited vulnerability (A) | **14 days** after a corrective or mitigating measure becomes available |
| Severe incident (B) | **1 month** after the Stage 2 notification |

Content: a description of the vulnerability including severity and impact; any
root cause if identified; and the corrective measures applied. For an incident:
nature and cause, mitigations applied, and cross-border impact if any.

### Stage 4 — Inform users: without undue delay
*Article 14(8) — for Trigger B, per Article 24(3); as a matter of policy, also for Trigger A.*

Inform affected users, and where necessary all users, about the vulnerability
or incident and about any corrective measures or actions they can take.
For us this means a published advisory plus announcement through OPC Foundation
channels, and embargo-list pre-notification to downstream integrators
(`cybersecurity-policy.md` §5).

Strictly, Article 24(3) binds us to Article 14(8) only for Trigger B. We do it
for both: a published advisory is the whole point of handling the vulnerability,
and withholding one because the regulation does not compel it would be
indefensible to the community that depends on this software.

---

## 3. During an incident — checklist

Work top to bottom. Record timestamps as you go; the sequence is itself
evidence of compliance.

```
[ ] T+0      Record the exact UTC time of awareness, and from whom. The clock starts here.
[ ] T+0      Name the incident lead. One person, not a group.
[ ] T+0      Open a private tracking record (see §4 template).
[ ] T+1h     Classify: Trigger A, Trigger B, both, or neither. Record the reasoning.
[ ] T+1h     If "neither" — record why, and exit to ordinary vulnerability handling.
[ ] T+2h     Identify affected versions from release tags and submodule SHAs.
[ ] T+4h     Draft the early warning. Do not wait for complete facts.
[ ] T+12h    Authorising person reviews and approves.
[ ] T+24h    >>> FILE EARLY WARNING via the SRP. Hard deadline. <<<
[ ] T+24h    Save the SRP reference number into the tracking record.
[ ] T+48h    Assess reachability in our build configuration; assess downstream impact.
[ ] T+48h    Pre-notify downstream integrators under embargo.
[ ] T+60h    Draft the Stage 2 notification.
[ ] T+72h    >>> FILE NOTIFICATION via the SRP. Hard deadline. <<<
[ ] ongoing  Develop the fix; keep the reporter informed.
[ ] on fix   Release with a version bump. Publish the advisory. Inform users (Stage 4).
[ ] +14d     >>> FILE FINAL REPORT (Trigger A: 14 d from measure available). <<<
[ ] +1mo     >>> FILE FINAL REPORT (Trigger B: 1 month from Stage 2). <<<
[ ] after    Post-incident review. Update this runbook with what went wrong.
```

If a deadline is going to be missed, file what exists at the deadline and note
that it is partial. Late and complete is worse than on time and partial.

---

## 4. Tracking record template

```
INCIDENT / VULNERABILITY RECORD
  ID:                     LDS-SEC-YYYY-NN
  Awareness (UTC):        YYYY-MM-DDTHH:MM:SSZ
  Source of awareness:
  Incident lead:
  Trigger classification: [ ] A: actively exploited vulnerability
                          [ ] B: severe incident, development infrastructure
                          [ ] Neither — reasoning:
  Active exploitation evidence:
  Affected components:
  Affected versions:      (tags + submodule SHAs)
  Reachable in our build: [ ] yes  [ ] no — reasoning:
  CVSS v4.0 base / vector:
  Downstream integrators notified:

  SRP FILINGS
    Early warning     due ______  filed ______  ref ______
    Notification      due ______  filed ______  ref ______
    Final report      due ______  filed ______  ref ______

  Coordinating CSIRT:
  Advisory URL:
  CVE ID:
  Fixed in version:
  Reporter / attribution:
```

---

## 5. Contacts

| Role | Contact |
|---|---|
| ENISA Single Reporting Platform | https://portal.cra-srp.enisa.europa.eu/ |
| SRP FAQ and user manual | https://www.enisa.europa.eu/cra-srp |
| SRP platform security issues | cra-srp-security@enisa.europa.eu |
| Coordinating CSIRT | `<<TBD: CCB / CERT.be — confirm, open item 5>>` |
| Incident lead (primary) | `<<TBD>>` |
| Incident lead (backup) | `<<TBD>>` |
| Authorising person | `<<TBD>>` |
| Legal counsel | `<<TBD>>` |

---

## 6. References

- Regulation (EU) 2024/2847, Articles 14, 15, 16, 24; Article 3(42); Recital 18
- [Commission CRA reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
- [ENISA SRP FAQ](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions)
- [ORC WG — Open Source Stewards and the CRA](https://orcwg.org/files/cra/resources/white-paper-on-open-source-software-stewards-and-cra.pdf)
