# Vendored Dependencies

This document tracks vendored third-party code that is committed directly into this repository.

## Current inventory

| Component | Location | Upstream | Version | Last reviewed | Notes |
|---|---|---|---|---|---|
| TweetNaCl | `src/tweetnacl.c`, `src/tweetnacl.h` | https://tweetnacl.cr.yp.to/ | 20140917 | 2026-02-04 | Local patches for detached signatures, `/dev/urandom`, and UBSan-safe carry math |

## Review policy

- Review vendored dependency metadata at least every 90 days.
- Update `config/vendored_deps.json` after each review.
- Run `scripts/check_vendored_dependencies.sh` locally before merging security-relevant changes.
