# Contributing to DAP

DAP is an open protocol. Contributions are welcome from anyone.

## Ways to contribute

**Feedback on the spec.** Open an issue if something is unclear, underspecified, or wrong. Real-world edge cases are especially useful.

**SDK implementations.** We need working code in multiple languages. See the `sdk/` section below.

**Examples.** Practical examples of credentials, discovery documents, and integration patterns. Put them in `examples/`.

**Translations.** The spec is maintained in English. Translations to other languages are welcome as separate files alongside the main spec.

**Pull requests.** Bug fixes, typo corrections, and improvements to existing code or docs.

## Principles

- **Concrete over abstract.** Working code and real examples beat theoretical discussions. If you propose a change, show what it looks like in practice.
- **Examples welcome.** Every new feature or field should come with an example credential or integration snippet.
- **Backward compatibility matters.** Breaking changes to the credential format or protocol flow need a strong justification and a migration path.
- **Keep it minimal.** v0.1 is intentionally narrow. Resist the urge to add features that belong in future versions.

## Structure for SDKs

SDK implementations live in `sdk/` and follow this layout:

```
sdk/
  python/
    dap_sdk/          # Principal, Agent, Service classes
    examples/
    README.md
  typescript/
    src/
    examples/
    README.md
```

Each implementation should include:

- Credential parsing and validation
- Signature verification (EdDSA and RS256)
- Discovery document handling
- A working example of the register flow
- Tests against the example credentials in `examples/credentials/`

## Process

1. Open an issue describing what you want to do (skip this for small fixes)
2. Fork the repo and work on a branch
3. Submit a PR with a clear description of the change
4. Maintainers will review and merge

## License

All contributions are licensed under Apache 2.0. By submitting a PR, you agree to this.
