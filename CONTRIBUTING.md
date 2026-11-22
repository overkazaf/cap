# Contributing to cap

Thanks for helping improve cap. This project is a research-oriented MITM proxy,
so changes that affect interception, certificate handling, device state, or
traffic rewriting need extra review.

## Development setup

- Go 1.27 or newer
- Node.js 18 or newer
- ADB and a rooted Android device for device integration work
- Optional reverse-engineering tools: Frida, jadx, radare2

## Daily workflow

```bash
make frontend-build
make build
make test
```

Use `GOCACHE=/private/tmp/cap-gocache` if your local Go cache is unavailable.

## Testing guidance

- Add package tests for new behavior.
- Keep network-dependent integration tests behind a build tag or skip when
  their required environment is absent.
- Do not check in regenerated frontend bundles unless a release preparation
  change requires them.
- Test Android changes on a real device when possible; explain the tested
  Android version and device/root configuration in the pull request.

## Security and safety

- Do not weaken TLS verification defaults without an explicit user opt-in.
- Do not log credentials or tokens by default.
- Cleanup device proxy/iptables state after setup commands.
- Treat remote scripts and patched APKs as untrusted input.
- Report sensitive vulnerabilities privately to the maintainer rather than in
  a public issue.

## Pull requests

1. Create a focused branch.
2. Add tests and update both English and Chinese documentation where needed.
3. Ensure `make test` and `make frontend-build` pass.
4. Describe reverse-engineering workflows in enough detail for reviewers to
   reproduce them.
