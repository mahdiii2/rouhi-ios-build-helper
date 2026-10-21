# Rouhi sealed iOS build tooling — local candidate

This repository-shaped folder is a local review candidate. It has not been
published. `policy.json` contains the two locally sealed and independently
verified input hashes, generated source snapshots and increasing build numbers
(customer1, driver4; version1.0). The reviewed account readback shows0.1GB used
of2GB included artifact storage and a$0 paid Actions budget that blocks paid
usage. Local policy is configured for a conservative200MiB total ciphertext
output budget, capped at100MiB per app with1day retention. Creating the public
repository, granting two input-secret accesses, uploading the exact encrypted
inputs and dispatching the two finite jobs still require the owner's explicit
approval. No real signing inputs or input decryption keys are included in this
generic folder.
The generic code is useful build tooling associated with the Rouhi software
project; neither private app is made public.

The workflow runs one selected app on the standard free `macos-15-intel` runner,
from an owner-only manual dispatch on main. It checks both the original actor
and the rerun actor, rejects rerun attempts, verifies the actual helper checkout
commit, and admits only the two exact ciphertext/source/manifest/build entries
sealed into the reviewed policy. No private-repository PAT is required. The
only user secret is an environment-scoped, per-input, base64-encoded random
32-byte AES key named `SEALED_INPUT_PASSPHRASE`; the name retains the proposal's
secret name but the value is a key, not a low-entropy password.

The customer and driver environments must permit main only and have owner-only
writers/dispatch actors. One initial owner approval can identify the exact
public generic commit, two sealed inputs, two environment-secret grants and two
finite dispatches. Required reviewers per run are optional; this candidate does
not require the sleeping owner to approve each run again. No source, ciphertext,
secret or code is being published by preparing this folder.

`prepare_payload.py` accepts only an explicit frozen source-row manifest and
explicit per-app private input map. It copies those files into an isolated local
directory, changes only the native builder's execution-context block, and makes
a reproducible *generated snapshot* Git commit there. It does not mutate the
owning repository, import its history, or pretend that snapshot is the original
private branch commit. Original and adapted source closure hashes remain
separate. The generated snapshot's context and the real public helper's
`GITHUB_*` context are checked separately; no GitHub identity is spoofed.

The existing native validator/signer is retained inside encrypted input. The
adapter adds a helper-context branch and leaves the original private-workflow
branch intact. Every byte outside that context block, including clean-source,
provider provenance, legal, profile, signing identity, export, permission,
privacy, Apple record and Apple binary validation gates, is unchanged. Upload
is fixed false in the controller and independently rejected by the helper
context guard. Apple binary validation is still a real network request during
an authorized future build; TestFlight upload and App Review are separate.

Input uses a dedicated streaming AES-256-GCM envelope. Output uses a fresh
AES-256-GCM key wrapped with the pinned owner's3072-bit RSA PUBLIC key using
RSA-OAEP-SHA256. This format is separate from the existing bounded Apple
diagnostic format. No output private key is sent to the runner. Changing input,
context, ciphertext, manifest or recipient fails authentication/identity checks.
Preexisting encrypt/decrypt destinations are preserved on rejection.

The controller downloads only the exact ciphertext release asset in this
helper's fixed GitHub repository; no cipher blob goes in Git history. It fully
authenticates before inspecting/extracting the uncompressed USTAR, validates
exact file closure, hashes, sizes and modes, and rejects links, devices,
traversal, aliases, duplicate names and unlisted members. It checks source again
after Git reconstruction and again in the private worker before importing the
native builder.

The private worker has an isolated HOME/source/temp/cache directory, private
bounded logs, and no input AES key, GitHub token, runtime token or unrelated
credential in its child environment. Original native private cleanup remains;
the wrapper retains only a bounded private tool-log tail before that cleanup.
All native output is redirected privately, including failures. The parent owns
a POSIX process group, terminates any remaining descendants even if its leader
already exited, and requires group quiescence before touching signing cleanup
or removing private files. If quiescence cannot be established it preserves the
private directory on the disposable VM and publishes no cleanup-completion
artifact. Cancellation or hard VM termination cannot be claimed as verified
cleanup.

The parent restores the original user keychain search list, removes only this
run's temporary keychain under its owned path, and removes the private tree.
Only encrypted `payload.sealed` and `completion.sealed` can reach artifact
upload. The second encrypted receipt records actual private-directory removal
and binds the payload ciphertext hash. Successful signing/validation alone does
not assert cleanup, device testing, TestFlight processing or full attestation.
Failure logs are encrypted too. There is no plaintext fallback.

This is ordinary trusted-source CI isolation, **not a kernel sandbox for
untrusted build scripts**. GitHub's runner and the approved source/dependencies
necessarily see plaintext while building. A malicious repository writer,
dependency, runner or source change can defeat workflow confidentiality;
owner-only access, exact review and dependency pins remain necessary. Public
metadata exposes the generic helpers, run timing/status, selected role/source
commit and ciphertext sizes/hashes. These are part of the proposed publication
scope. GitHub's terms require a genuine association with the software project;
they do not expressly approve this encrypted private-input architecture.

Current official docs say standard public macOS compute is free and unlimited;
larger runners and artifact storage are different. The candidate never chooses
a paid runner or uploads dependency caches. Its resource checks require actual
hosted Intel Darwin, Xcode/iOS26+, Java21, Python3.12, existing Android35/36 SDK
inputs, at least12GiB RAM and12GiB available disk. Each job is capped at90min,
the native worker at75min, and outputs at the reviewed remaining free artifact
capacity. The owner's initial account storage/no-paid-usage readback supplies
that capacity; no billing credential is added to the job. Artifacts retain1day
and should be deleted after verified local retrieval. Local policy pins the two
verified seals, generated source snapshots and increasing build numbers, with
the reviewed200MiB total/100MiB per-app conservative output limits. It does not
authorize publication, new secrets or dispatch by itself.

Run synthetic tests with Python3.12 plus `requirements-macos.txt`:

```text
python3 -B -m unittest discover -s tests -v
```

The Windows synthetic tests exercise streaming encryption, tampering, tar
rejection, deterministic Git reconstruction, identity separation, capacity and
input allowlists, captured child output/timeouts, encrypted success/failure,
and cleanup failure. POSIX process-group behavior is tested through controlled
signals/mocks; actual hosted Mac/Xcode execution remains unverified. The
separate local native-adapter check also runs both original native guard suites
against adapted copies. No private app source is a public test fixture.

Official references:

- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/billing/concepts/product-billing/github-actions
- https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow
- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features
- https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md
