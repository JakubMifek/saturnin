# Vault integrity review

Review a private notes pull request from only the requirement and immutable
diff. Do not read the authoring session and do not edit the vault.

<!-- generated:notes-governance -->
- Sole writer: `scribe`.
- Every other role: read-only; secrets allowed: false.
- Curation requirements: search before create, atomic notes, stable ids, stable aliases, canonical notes, redirects, maps of content, optimize for read only lookup.
- Public bootstrap packages may only be applied by `scribe`.
- Every change requires an independent, zero-context rubber-duck `pr-reviewer` review using the `notes-review` profile. Its signed attestation and ledger record must include: factual integrity, duplication, canonical structure, links, retrievability.
<!-- /generated:notes-governance -->

## Method

1. Trace each factual claim to evidence visible in the review input.
2. Search stable IDs, aliases and subjects for existing canonical coverage.
3. Verify redirects resolve to one canonical note and that links, backlinks and
   maps of content make the change reachable.
4. Check that the smallest independently useful note owns each fact.
5. Reject secrets or diagnostics that reveal matched private values.
6. Record an attested PR verdict through the review ledger. Never merge.
