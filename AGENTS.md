# AGENTS

## Project Overview

- This repository is `zzupy`, a Python library that wraps Zhengzhou University mobile-app and web services.
- Main public modules live under `zzupy/app`, `zzupy/web`, and `zzupy/aio`.
- Sync and async clients intentionally mirror each other. When changing behavior in `zzupy/app` or `zzupy/web`, check whether the same change is also needed in the corresponding `zzupy/aio` module.
- Data contracts are centralized in `zzupy/model`. Shared helpers live in `zzupy/utils.py`, and project-specific exceptions live in `zzupy/exception.py`.

## Stack And Tooling

- Python packaging is defined in `pyproject.toml`; the build backend is Hatchling.
- Use `uv` for environment management, installs, and project commands.
- Common verification commands:
  - `uv sync`
  - `uv build`
  - `ruff check`
- There is currently no dedicated test suite in `tests/`; for most changes, at least run a build and a lightweight syntax check.
- Docs are built with MkDocs Material. If you change public APIs or user workflows, update the relevant docs in `docs/` and verify with `uv sync --extra docs && uv run mkdocs build` when practical.

## Code Conventions

- Follow the existing Chinese-first documentation style for docstrings, logs, and user-facing error messages unless a file already uses another style.
- Keep implementations simple and explicit. This codebase prefers straightforward `httpx` request flows over heavy abstraction.
- Reuse the existing exception types from `zzupy/exception.py` instead of raising generic exceptions for domain failures.
- Preserve the current logging style with `loguru`, including request/response diagnostics where a module already uses them.
- Keep type hints modern and consistent with the codebase, including `| None` unions and Pydantic v2 APIs such as `model_validate`.
- Put schema parsing and normalization in models or small helpers when possible; avoid duplicating response-shape handling across clients.

## API Client Guidance

- Most clients wrap reverse-engineered upstream services. Avoid speculative refactors that might change request headers, params, cookie handling, or encryption details unless required.
- Preserve login state behavior, token refresh flows, and context-manager semantics (`__enter__`, `__exit__`, `close`, `logout`) when modifying clients.
- When adding a new campus service, prefer matching the existing layout: client in `zzupy/app` or `zzupy/web`, async counterpart in `zzupy/aio`, models in `zzupy/model` if needed, and exports in the relevant `__init__.py`.
- If a response is validated with Pydantic in the sync client, keep the async client aligned.

## Documentation And Release Notes

- Public surface changes should usually update `README.md` and the relevant usage docs under `docs/usage/`.
- API reference pages are generated from code, so exported symbols and docstrings matter.
- Versioning and release automation are handled through `python-semantic-release`; do not manually change release flow unless the task explicitly requires it.

## Workspace Hygiene

- The working tree may contain unrelated user changes or untracked files. Do not remove or overwrite them unless the user explicitly asks.
- In particular, check `git status` before broad edits, and limit changes to files relevant to the task.
