# Runtime dependencies

The corrected remediation uses Python 3.9 standard-library modules only.
It does not import requests, urllib3, certifi, charset_normalizer, or idna.

`cacert.pem` is copied unchanged from the original
`certifi/cacert.pem` (certifi 2026.7.22). Its license is in
`cacert-LICENSE.txt`. Python loads this PEM data directly, in addition to
its system trust store; no certifi Python code is needed.

The original third-party directories remain in this checkout for reference.
The build script excludes them from the FMC archive. In particular, requests
2.34.2 and urllib3 2.7.0 require Python >=3.10, and the charset_normalizer wheel
contains CPython 3.13 Windows extensions. They are unsuitable dependencies
for the reported FMC Python 3.9.9 environment.

To maintain the trust bundle, replace cacert.pem with a current, trusted
Mozilla/certifi PEM bundle and retain its license. Rebuild the archive afterward.
Do not disable certificate or hostname verification to resolve TLS failures.
