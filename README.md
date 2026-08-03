# acme_client

[![License](https://img.shields.io/github/license/ownjoo/acme_client)](LICENSE)
[![Top language](https://img.shields.io/github/languages/top/ownjoo/acme_client)](https://github.com/ownjoo/acme_client) [![Stars](https://img.shields.io/github/stars/ownjoo/acme_client)](https://github.com/ownjoo/acme_client/stargazers) [![Forks](https://img.shields.io/github/forks/ownjoo/acme_client)](https://github.com/ownjoo/acme_client/forks) [![Issues](https://img.shields.io/github/issues/ownjoo/acme_client)](https://github.com/ownjoo/acme_client/issues) [![Pull requests](https://img.shields.io/github/issues-pr/ownjoo/acme_client)](https://github.com/ownjoo/acme_client/pulls)
Minimal ACME protocol client — talks directly to an ACME directory (e.g. Let's Encrypt)
using JWS-signed requests (`python-jose`/`josepy`), without a full ACME library. Handles
directory discovery, nonce fetching, and signing requests with your account key.

# SECURITY NOTE:
I wrote the .py files.  You have my word that they don't do anything nefarious.  Even so, I recommend that you perform
your own static analysis and supply chain testing before use.  Many libraries are imported that are not in my own control.
