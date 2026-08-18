# Releasing

How a new version of `clevercloud-sdk` reaches PyPI. Publishing is manual and
run from a maintainer's machine: there is no publishing workflow and no PyPI
token stored in the repository.

A published version is **permanent**. PyPI does not allow reusing a version
number, even after deleting a release — a mistake can only be *yanked*, which
hides it from resolvers without freeing the number. Everything below is
ordered so the irreversible step comes last.

## Prerequisites

- Maintainer rights on the [`clevercloud-sdk`](https://pypi.org/project/clevercloud-sdk/)
  PyPI project.
- A PyPI API token, created under **Account settings → API tokens**, scoped to
  this project rather than to the whole account.
- [`uv`](https://docs.astral.sh/uv/) installed locally.

## 1. Prepare the version

Pick the number according to [semantic versioning](https://semver.org/): a
breaking change to the public API means a new major (or minor while `0.x`).

Update it in **both** places — they are not derived from one another, and a
mismatch is only visible after publication:

- `version` in `pyproject.toml`
- `__version__` in `src/clever_cloud/__init__.py`

Then add the release section to `CHANGELOG.md`, keeping the existing headings:
Security, Fixed, Added, Breaking changes. Anything that forces users to touch
their code belongs under **Breaking changes**, with the migration in one line.

## 2. Check the working tree

```bash
uv sync --extra dev
uv run ruff check .
uv run mypy
uv run pytest --cov
```

All three must pass. CI runs the same on Python 3.11, 3.12 and 3.13; run it
locally against the oldest supported version if you touched anything typing- or
syntax-related:

```bash
uv run --python 3.11 --extra dev --isolated pytest
```

## 3. Merge, then tag

Land the changes on `main` through a pull request, then tag the **merge commit**
so the tag points at reviewed code:

```bash
git checkout main && git pull
git tag -a v0.2.0 -m "v0.2.0

<short summary, one line per significant change>"
git push origin v0.2.0
```

Tags are named `vMAJOR.MINOR.PATCH`. Annotated (`-a`), not lightweight, so the
tag carries an author, a date and a message.

## 4. Build and verify

```bash
rm -rf dist
uv build
uvx twine check dist/*
```

`twine check` validates the metadata PyPI will reject at upload time. Also
confirm the wheel ships the typing marker — the package advertises
`Typing :: Typed`, and without this file type checkers ignore the annotations
entirely:

```bash
python -m zipfile -l dist/*.whl | grep clever_cloud/py.typed
```

Optionally, install the built artifact in a throwaway environment and import it,
which catches a broken package that still builds fine:

```bash
uv run --isolated --no-project --with dist/*.whl python -c "
import clever_cloud; print(clever_cloud.__version__)"
```

## 5. Publish to PyPI

Test it against TestPyPI first if anything about the packaging changed:

```bash
uv publish --publish-url https://test.pypi.org/legacy/ --token <test-token>
```

Then publish for real. This is the irreversible step:

```bash
uv publish --token <pypi-token>
# or: UV_PUBLISH_TOKEN=<pypi-token> uv publish
```

Pass the token on the command line or through `UV_PUBLISH_TOKEN`; do not write
it into a file in the repository.

Verify the result:

```bash
uv run --isolated --no-project --with clevercloud-sdk==0.2.0 python -c "
import clever_cloud; print(clever_cloud.__version__)"
```

## 6. Create the GitHub release

Publish the release notes from the CHANGELOG section for this version, and
attach the artifacts you just uploaded so both distributions are archived
outside PyPI:

```bash
gh release create v0.2.0 \
  --title "v0.2.0 — <headline>" \
  --notes-file <notes.md> \
  dist/clevercloud_sdk-0.2.0-py3-none-any.whl \
  dist/clevercloud_sdk-0.2.0.tar.gz
```

## If something went wrong

A bad version cannot be replaced. Yank it, then publish a fixed one:

```bash
# On pypi.org: project → Manage → Releases → Options → Yank
```

Yanking keeps the files available for anyone who pinned that exact version, but
stops resolvers from picking it up. Then bump to the next patch version and go
through this document again — never try to reupload the same number.
