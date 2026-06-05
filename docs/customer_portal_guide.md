# Customer Portal Guide

This guide walks you, as an AAC tenant user, through everything the
portal does — from signing in for the first time to shipping a signed
policy bundle to your AAC bridge.

> **Audience:** the human at your organization who owns compliance
> policy authorship. No infrastructure knowledge required; some
> familiarity with what "OPA Rego" is is useful but not assumed.

## Contents

1. [Signing in and MFA](#1-signing-in-and-mfa)
2. [The two paths to a policy](#2-the-two-paths-to-a-policy)
3. [Path A — Upload a written policy](#3-path-a--upload-a-written-policy)
4. [Path B — Fork from the standard library](#4-path-b--fork-from-the-standard-library)
5. [Reviewing per-target Rego](#5-reviewing-per-target-rego)
6. [Publishing](#6-publishing)
7. [Building and shipping the signed bundle](#7-building-and-shipping-the-signed-bundle)
8. [Audit log](#8-audit-log)
9. [Creating a new version (republish)](#9-creating-a-new-version-republish)
10. [What to do if something goes wrong](#10-what-to-do-if-something-goes-wrong)

## 1. Signing in and MFA

Your operator (Red Hat, your service provider, or your internal admin)
creates your account against your tenant. You'll receive an invite
with a one-time password to set; from then on you sign in at
`/portal/login` with your email + password.

The first sensitive action you take (uploading a policy, publishing,
building a bundle) will require **two-factor authentication**. If you
haven't yet enrolled, the portal walks you through scanning a QR code
into your authenticator app and verifying one TOTP code; from then on
each new browser session asks you for a 6-digit code on the way in.

If you ever suspect your account has been compromised, hit **Sign out
of all devices** on the home page — this invalidates every session
your user has anywhere, immediately.

## 2. The two paths to a policy

Every customer-side policy starts in one of two ways:

- **Path A — Prose upload.** You hand the portal a written document
  (PDF, DOCX, ODT, Markdown, or plain text). The LLM reads it,
  extracts a structured set of control intents, and generates Rego
  for each target system you tell us about.
- **Path B — Fork from the standard library.** You start from one of
  our existing Rego modules (CIS, NIST, ISO 27001, …) and make
  per-tenant edits on top of it. The diff against upstream is
  preserved forever so you can see exactly what you customized.

Both paths converge on the same review + publish + bundle workflow.
The choice is about how you author, not what you ship.

## 3. Path A — Upload a written policy

From the home page, click **Upload a policy**. You'll be asked for:

- **Name** — what the policy is called inside the portal (your name,
  not ours).
- **Framework bucket** — which OPA bundle this gets evaluated against
  (`iso27001`, `pci_dss`, `nist_800_53`, etc.). One framework per
  policy; if you need to publish controls across frameworks, create
  one policy per framework.
- **File** — the actual document. PDF, DOCX, ODT, Markdown, or plain
  text. There's a 10 MB cap.

The upload lands as a **draft**. From the policy detail page:

1. **Extract IR** — the LLM reads the document and produces a
   structured intermediate representation: a list of controls, each
   with intent, scope, and a target system. You can see the control
   count and re-run extraction if you're not happy.
2. **Generate Rego** — the portal picks the right approach per
   control: template-mapped when our library has a matching pattern,
   LLM-generated when it doesn't. Every generated Rego module is run
   through `opa check` server-side before it lands. Failures surface
   on the target with the parse error so you can edit.

## 4. Path B — Fork from the standard library

From the home page, click **Browse standard library**. You can drill
into the file tree (CIS / NIST / ISO 27001 / etc.) and open any
`.rego` file to preview its source.

Click **Fork this file** on a preview page to start a per-tenant
overlay. The fork:

- Creates a new policy in your tenant pinned to the *exact* upstream
  version you saw (the upstream sha is recorded).
- Inherits the file's structure as a single target.
- Lands as a **draft** for you to review and edit.

If upstream later moves (the standard library gets updated), the
**View diff vs upstream** link on the policy detail page renders a
unified diff between your overlay and the current upstream, so you
can decide whether to merge the upstream change into your overlay.

## 5. Reviewing per-target Rego

Whether you came from Path A or Path B, you land at the same place:
the **policy detail** page with a list of targets. Each target is one
Rego module — typically one per OS, cloud, or container family
(linux/rhel9, windows/2022, aws, k8s, ...).

Click a target row to open the per-target review screen. Here you can:

- **Read the Rego** — the generated source is shown read-only.
- **Edit** — replace the Rego with your own. On Save, the server
  re-runs `opa check`. If it fails, the parse error appears inline
  and the page stays in edit mode so you can fix and resubmit. Any
  edit resets the target's status back to **pending review**.
- **Approve** — the target is eligible to ship in the next bundle.
  You can optionally record *why* you approved it; that note shows
  up in the audit log.
- **Reject** — the target is excluded from bundles until edited or
  re-approved. A reason is **required** for rejection — partly to
  force a paper trail, partly because future-you needs to know what
  was wrong.

The status badge on each target row is one of `pending` (default),
`approved`, or `rejected`.

## 6. Publishing

Once you've approved at least one target, the policy can be
**published**. From the policy detail page, the Publish section shows
your live "X / Y approved" counter and gates the Publish button on
`X > 0`.

Click Publish, confirm, and the policy moves to status `published`.
**This is a one-way operation:** once published, the targets are
frozen. To change anything, create a new version (see §9).

After publish, the policy detail page surfaces:

- A **published** badge.
- A **Go to bundles →** button to take you to the next step.
- A **Create new version** subsection for republishing.

## 7. Building and shipping the signed bundle

The **bundle** is what your AAC bridge actually loads into OPA. It's
a `tar.gz` of every approved + published target's Rego, plus a
manifest, signed by the portal so the bridge can verify what it's
loading.

From `/portal/bundles`:

- **Build bundle** — folds every published+approved target across
  every published policy in your tenant into a single signed bundle.
  The build is idempotent in effect: the same approved set produces
  the same bytes. Each build inserts a new row; the most recent row
  is **current**.
- **Current bundle** — the live metadata: SHA-256, byte size,
  signing key ID, target count, and the list of source policies that
  contributed to the bundle.
- **Excluded targets** — appears only if the builder dropped any
  approved targets at build time (typically because their saved Rego
  no longer passes `opa check`). The reason for each exclusion is
  shown so you can open the target and re-edit.
- **Builder manifest** — the raw per-target metadata from the
  builder. Click Show to expand. Useful for forensic deep-dives.
- **History** — every prior bundle, reverse-chronological. Click any
  row to drill into its full manifest detail. Each row shows who
  built it (the operator email) and how many targets were included.

You don't need to do anything to "ship" the bundle. Your operator's
**bridge** runs continuously alongside your AAC OPA deployment and
polls the portal at its configured cadence (usually every few
minutes). When the current bundle SHA changes, the bridge pulls,
verifies the signed envelope using the portal's published public key,
and reloads OPA.

## 8. Audit log

Every state change on a policy is recorded in an append-only audit
log. From any policy detail page, click **Audit log →** in the
header.

You'll see — newest first — every:

- upload
- IR extraction
- Rego generation
- target approval / rejection / edit
- publish
- republish (target copied into a successor draft)

Each row shows the action, the actor's email (or `(user removed)` if
the user has since been deleted), the wall time, and a click-to-expand
JSON details view with the action-specific metadata.

Use this when an auditor asks "who approved Linux/rhel9 on this
policy, and when?" — the answer is one click away.

## 9. Creating a new version (republish)

When the published policy needs to change, you don't edit it in place
— you create a successor draft. The original published row is
immutable (a database trigger enforces it) so your historical bundle
record always reflects what actually shipped.

From the published policy's detail page, the Publish section now
includes a **Create new version** subsection:

- **Leave the version blank** — the server bumps the patch component
  of the parent's version (e.g. `v1.0.0` → `v1.0.1`).
- **Enter a custom version** — for major or minor bumps (`v2.0.0`).

The new draft is a complete copy: same IR, same source document,
same target rows with their prior review verdicts preserved (because
identical Rego content means the prior verdict still applies). You
land on the new draft's detail page ready to edit.

Build a new bundle after the new draft is published and the bridge
picks it up on its next poll.

## 10. What to do if something goes wrong

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Upload returns 422 with a parser error | Document format isn't one of the 5 supported, or extraction yielded zero text | Convert to PDF or plain text and retry |
| Generate Rego completes but a target is rejected | Initial `opa check` failed on the LLM output | Open the target, click Edit, fix the parse error, Save (the server re-runs `opa check`) |
| Publish button stays disabled | No targets are approved | Open the targets table and approve at least one |
| Bundle's `excluded_target_count` is non-zero | A previously-approved target's Rego no longer passes `opa check` (often because of an upstream OPA upgrade) | Open the target via the excluded-targets table, re-edit, re-approve, build again |
| The bridge is loading an old bundle | The bridge cache is stale, or the bridge hasn't polled yet | Wait one poll cycle; or ask your operator to force a reload |
| You see `(user removed)` on an audit row | The actor's tenant_users row was deleted | Expected — audit records survive user deletion via `ON DELETE SET NULL` so the history isn't lost |
| Login redirects you in a loop | Your session expired or was revoked from another device | Sign in fresh; if it persists, ask your operator to reset your password |

If the portal returns an error you don't recognize, the error message
itself is what your operator's on-call team will ask for. Screenshot
the page and forward it.

## Related documentation

- `policy_ingestion_design.md` — architecture deep-dive for engineers
- `architecture.md` — portal + bridge topology
- `cve_intelligence_architecture.md` — adjacent CVE feed pipeline
