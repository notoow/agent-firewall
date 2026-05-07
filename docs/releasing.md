# Releasing

AgentFirewall releases are tag-driven.

## Release Checklist

1. Update `CHANGELOG.md`.
2. Update `project.version` in `pyproject.toml`.
3. Run local checks:

```bash
python -m pytest
python -m build
python scripts/check_version.py
```

4. Commit the release prep.
5. Create and push a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `Release` workflow will:

- run tests on Python 3.11, 3.12, and 3.13
- verify the tag matches `pyproject.toml`
- build source and wheel distributions
- create a GitHub release with distribution artifacts
- publish to PyPI through Trusted Publishing

## PyPI Trusted Publishing

The release workflow uses `pypa/gh-action-pypi-publish@release/v1`, the PyPA Trusted Publishing action recommended by PyPI.

Before the first PyPI release, configure a Trusted Publisher on PyPI:

- PyPI project: `agent-firewall`
- Owner: `notoow`
- Repository: `agent-firewall`
- Workflow: `release.yml`
- Environment: `pypi`

The GitHub repository also needs an environment named `pypi`. Environment protection rules are recommended.

Useful references:

- https://docs.pypi.org/trusted-publishers/
- https://docs.pypi.org/trusted-publishers/using-a-publisher/
- https://github.com/pypa/gh-action-pypi-publish

## Recovering From A Failed Release

If the GitHub release job succeeds but PyPI publish fails because Trusted Publishing is not configured, fix the PyPI publisher settings and rerun the failed workflow job.

Do not reuse a version once it has successfully reached PyPI. Bump `pyproject.toml`, update `CHANGELOG.md`, and tag a new version.
