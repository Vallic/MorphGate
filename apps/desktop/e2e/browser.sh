#!/bin/sh
# What the app opens sign-in pages with during e2e (MORPHGATE_BROWSER): follows the redirects
# like a browser, from the identity provider back to the sync server.
exec curl -sSL --max-time 30 -o /dev/null "$1"
