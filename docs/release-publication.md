# Release publication

Before creating a release, the operator verifies that GitHub immutable releases are enabled for
the repository. The Actions token cannot read or change that repository Administration setting, so
the workflow does not attempt to query or mutate it. An exact annotated release tag and its peeled
commit are revalidated against `main` immediately before every externally visible publish or
attestation operation.

Before any image build, the workflow enumerates bounded authenticated Releases-list pages and fully
verifies an exact final immutable Release, including its source binding, registry digest, and both
downloaded assets; an exact match is reused without rebuilding. An exact matching draft is also
recovered only after its complete asset set, API digests and sizes, and downloaded bytes are verified.
Otherwise the workflow creates one exact `gh release create --verify-tag --draft` result, verifies the
draft, and promotes that same draft with `gh release edit --draft=false`. If a later promotion step
fails, a rerun can recover the exact draft or final release and repeat the bounded verification.
Final verification requires the tag, peeled annotated-tag commit, complete asset set, API asset
digests and sizes, downloaded bytes, IDs, and `immutable: true` state. Any mismatch fails closed.

GitHub's immutable-release feature supplies a release attestation for the published tag and its
assets. Separately, the workflow attaches one build-provenance attestation to the exact registry
image digest before the immutable Release is created, after its single-platform smoke checks; it
does not maintain a second signing system.

`controlplane-<tag>.digest.json` binds, in deterministic key order, the image repository, release
tag, source commit, annotated tag object, and canonical registry digest. GitHub's immutable-release
attestation covers this asset and the separately tested tier-controller wheel. The Go image build
exports a tested local archive and a run-scoped GHCR staging reference; the version tag is created
only after runtime checks from that exact full manifest digest. A pre-existing exact image tag is
never reused. Only a complete exact immutable Release, or a complete exact draft that is verified
before promotion, may be reused.

The workflow proves absence before creating a version tag and refuses every pre-existing exact
version tag. GHCR does not document an atomic “push only if this tag is absent” operation, so an
external writer that wins the check-and-create race is detected by the final digest check and fails
closed.
