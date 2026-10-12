# Contributing

`e2ee-reports` is free software under AGPL-3.0. Contributions, review, and critique are welcome.

A prototype reference implementation exists (see the README for what it covers). The most valuable contributions right now are review of the protocol, the threat model, and the key schedule in `src/`:

- Read [docs/threat-model.md](docs/threat-model.md) and [docs/protocol.md](docs/protocol.md).
- Open an issue to question an assumption, point out a gap, or propose an alternative construction. Concrete, specific feedback is more useful than general impressions.
- For anything that touches confidentiality of reports or reporters, see [SECURITY.md](SECURITY.md) and report privately rather than in a public issue.

## Building and testing

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same three commands. If you change the wire format or key schedule on purpose, regenerate the vectors with `cargo test --test vectors -- --ignored --nocapture print_vectors` and explain the change in the pull request.

## Licensing of contributions

By contributing you agree that your contribution is licensed under AGPL-3.0, the same license as the project.

## Conduct

Be straightforward and respectful. Engage with the strongest version of the argument or design under discussion. Disagreement on technical merits is expected and welcome; personal hostility is not.
