# Contributing to Transport Lookout

## Before opening a pull request

- Keep changes scoped and add or update tests for behavior changes.
- Run `ruff check .` and `pytest -q` from the repository root.
- Run `npm run build` from `ui/` when changing the operator console.
- Do not commit `.env` files, access tokens, scan artifacts, or customer network data.

## Pull requests

Describe the operational or security impact, how the change was tested, and any deployment or migration requirements. Changes affecting scan authorization, worker execution, identity, or data retention require explicit security review.

