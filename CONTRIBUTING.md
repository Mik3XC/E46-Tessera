# Contributing

E46 Tessera is being prepared for local experimentation. A public collaboration
repository and release process will be announced separately.

Keep changes small and explain their purpose, affected behavior, and how they
were checked. Build with the documented dependency versions. Preserve existing
license notices and use the repository's formatting configuration.

Changes to serialization, hashing, address encoding, difficulty, emission,
signature handling, genesis or checkpoints can change compatibility. Identify
those effects explicitly. Keep the built-in provider self-check enabled.

The independent GOLD and research test collections are outside this tree.
Do not infer protocol correctness from a successful compile. Record checks
actually performed and any coverage still outstanding.

Keep runtime wallets, keys, fingerprints, chain stores, local paths and generated
artifacts out of commits. Use public dummy data when discussing examples.

This staging tree has no release automation, tags, binary distribution, or
configured GitHub remote. Publishing and release decisions are separate steps.
