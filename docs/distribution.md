# Distribution & Release Process

This repo ships `mcp-guard` two ways:

1. **Wheel** attached to a GitHub Release (Python users, CI gates).
2. **Docker image** at `ghcr.io/windshock/mcp-guard` (security ops, isolated environments).

Both artefacts are produced by `.github/workflows/release.yml` whenever a `v*` tag is pushed. The lab benchmark (`docker compose`) is a separate concern and is not part of this distribution.

## Cutting a release

```bash
# 1. Bump the version in guard/pyproject.toml (e.g. 0.1.0 -> 0.2.0)
$EDITOR guard/pyproject.toml

# 2. Smoke build locally before tagging
python -m pip install --upgrade build
python -m build guard/
python -m venv /tmp/v && /tmp/v/bin/pip install guard/dist/*.whl
/tmp/v/bin/mcp-guard --help

# 3. Tag and push
git commit -am "release: v0.2.0"
git tag v0.2.0
git push origin main --tags
```

The push triggers `release.yml`, which:

- builds wheel + sdist from `guard/`
- attaches both to the GitHub release page (auto-generated from commit log)
- builds `Dockerfile.dist` against the same wheel
- pushes `ghcr.io/windshock/mcp-guard:0.2.0` and `:latest`

## First-time setup (one-off)

### 1. GHCR package visibility

The very first push creates a **private** package under `ghcr.io/windshock/mcp-guard`. To let anyone `docker pull` it:

1. Go to https://github.com/users/windshock/packages/container/mcp-guard/settings
2. Scroll to **Danger Zone → Change package visibility**
3. Set to **Public**

You only need to do this once; subsequent pushes preserve the visibility.

### 2. Repository permissions

`release.yml` writes to:

- the GitHub Release (needs `contents: write`)
- GHCR (needs `packages: write`)

Both are declared at the workflow level via `permissions:`. The default `GITHUB_TOKEN` is sufficient — no extra secret needed.

### 3. (Optional) Move to PyPI later

If/when you want `pip install mcp-guard` to work without an explicit URL:

1. Register the project on https://pypi.org and configure a Trusted Publisher pointing at this repo + `release.yml`.
2. Add a `publish-pypi` job to `release.yml`:
   ```yaml
   - uses: pypa/gh-action-pypi-publish@release/v1
     with:
       packages-dir: guard/dist/
   ```
3. The wheel attachment to GitHub Releases can stay as a redundant install path.

## Verifying a release

```bash
# Wheel install in a fresh venv
TAG=v0.2.0
python -m venv /tmp/v
/tmp/v/bin/pip install "https://github.com/windshock/mcpscan/releases/download/${TAG}/mcp_guard-${TAG#v}-py3-none-any.whl[cisco]"
/tmp/v/bin/mcp-guard scan --path . --with-cisco --output json | head

# Docker pull + smoke
docker pull ghcr.io/windshock/mcp-guard:${TAG#v}
docker run --rm -v "$PWD:/scan" ghcr.io/windshock/mcp-guard:${TAG#v} scan --path /scan/servers/vuln-exec --output json
```

## Hotfix / re-release

If a release ships broken: bump the patch version, retag, push. The release workflow is idempotent — a re-run on the same tag will overwrite the assets and Docker tags.

```bash
# Don't reuse the same tag — bump and re-tag.
git tag v0.2.1
git push origin v0.2.1
```
