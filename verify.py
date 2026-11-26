#!/usr/bin/env python3
"""Standalone CLI entrypoint for the post-reproduction Automated Verifier."""
from __future__ import annotations

import sys

from verifier.main import run_cli

if __name__ == "__main__":
    sys.exit(run_cli())
