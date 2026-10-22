#!/bin/sh
# What the app opens web pages with during e2e (MORPHGATE_BROWSER): follows the redirects like a
# browser, from the identity provider back to the sync server. Pages off this computer (the docs,
# GitHub) aren't fetched; every address is noted in E2E_BROWSER_LOG when it's set.
[ -n "${E2E_BROWSER_LOG:-}" ] && echo "$1" >>"$E2E_BROWSER_LOG"
case "$1" in
  http://127.0.0.1[:/]* | http://localhost[:/]*) exec curl -sSL --max-time 30 -o /dev/null "$1" ;;
esac
