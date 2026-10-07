# Registry contract inputs

[Registry v2](registry-v2/README.md) is an exact copy of the hub's implementation candidate.
It is not a released or formally accepted contract. Runtime builds require no sibling checkout
or network access after dependencies have been fetched. The component test verifies every
bundle file and the pinned aggregate digest.

Source preparation lives in the hub's `experiment/reg-01-contracts` branch, based on
`c46f86400732223a6a7c23f5d186250ab4a144eb`. The actual Registry candidate source is
[hub commit `dff725159fd02035589ad2f78ce74db7f1bd7329`](https://github.com/iokaio/munarium-platform/tree/dff725159fd02035589ad2f78ce74db7f1bd7329/docs/decisions/registry-v2).
Both this immutable source revision and the bundle digest pin the consumed inputs.
Future updates replace the
bundle only through a reviewed contract change; do not hand-edit the vendored files.

[Identity v1](identity-v1/README.md) adds the unchanged foundation and Warden admission
bundles from the public hub base `c46f864`. The Registry manifest bundle's semantic README
now references ADR 0006 and the recipient identity adapter; its new aggregate is
`2e121d86c8dd4061ef1bdbc9dc073dceebfebf7305cf7a50d5d0e59385eaf0fc`.
Its manifest schemas, trust fixture and 32 signed artifacts are unchanged from the earlier
local candidate. The old aggregate was
`692b258e6988c426ece6f65c946a4972e226d3b854c1dee983c359db08a92cef`.
