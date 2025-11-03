# Contributing

## Branching & PRs
- Create feature branches from `main`. Small, focused PRs.
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, etc.).

## Versioning (mirrors DISA STIG)
- We pin MAJOR.MINOR to the STIG **major/minor**.
- Current STIG: **V2R4** → repo **2.4.x**.
- Only bump **PATCH** for regular updates (2.4.1, 2.4.2, ...).
- When DISA publishes a new major/minor (e.g., V3R1 or V2R5), we align and set repo to `3.1.0` or `2.5.0` accordingly.

## Releases
- Use the **Release** workflow (`release.yml`) with input `new_version` that matches `^2\.4\.\d+$`.
- The workflow updates `inspec.yml`, regenerates `CHANGELOG.md`, tags, and creates a GitHub Release.

## Testing
- `bundle install` (Ruby) if needed.
- `cinc-auditor check .` to validate the profile.
- `cinc-auditor exec . --input-file=examples/inputs.yml` for local runs.

## Style
- Ruby: `rubocop` (see `.rubocop.yml` if present).
