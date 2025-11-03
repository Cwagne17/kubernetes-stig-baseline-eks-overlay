# Copilot / Agent Tasks

## "Finish bootstrap" (idempotent)
- Replace README with project badges and quickstart.
- Ensure `.github/workflows/{validate,test,release}.yml` exist.
- Create/maintain `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`.
- Insert custom code markers into all `controls/*.rb` files:
  - Add **exactly** these two lines after the last `tag ...` in each control block and before its final `end`:
    - `# --- Begin Custom Code ---`
    - `# --- End Custom Code ---`
  - **No other content changes**.

## "Patch release"
- Input: `new_version` matching `^2\.4\.\d+$`.
- Update `inspec.yml` `version:` to `new_version`.
- Rebuild `CHANGELOG.md` (append entry).
- Create tag and GitHub Release with body from changelog.
