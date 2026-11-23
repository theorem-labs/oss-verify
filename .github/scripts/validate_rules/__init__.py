# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The rules of `oss-verify validate`, for the jobs that hold a token and the jobs whose outputs they read, which load
no code from src/ (tests/test_token_jobs.py): validate.py is src/oss_verify/validate.py, and check_build.py what it
uses of src/oss_verify/check_build.py. .github/scripts/copy-validate-rules writes both, and says why;
tests/test_validate_rules.py fails while they differ from what it writes.

    from validate_rules import validate                            # beside .github/scripts on sys.path
    PYTHONPATH=.github/scripts python3 -P -m validate_rules.validate projects/<name>   # oss-verify validate
"""
