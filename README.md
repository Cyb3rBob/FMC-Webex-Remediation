# FMC Webex remediation module

Version 1.4 targets the reported FMC 7.6 environment with Python 3.9.9.
It posts a message to a Webex space when an associated correlation rule triggers.
No third-party Python packages or pip installation on FMC are required.

## Version 1.4: source IP address

Every message now includes **Source IP**. The module requests Cisco's optional
`src_ip_addr` event field, as documented in the
[source host data reference](https://www.cisco.com/c/en/us/td/docs/security/firepower/60/api/remediation/FireSIGHT-System-Remediation-API-Guide/WritingRemedClients.html).
Missing, blank, `undefined`, `null`, or `(null)` values display
`IP-not-identified`. Missing IP information never prevents the notification.

The source IP is the fourth event argument, after OS vendor, product, and
version. Existing three-field manual commands still work and show the fallback.
Install the complete version 1.4 archive and configure a new instance/action,
including the proxy URL if needed, then update the correlation rule response.
The script and template must be upgraded together for FMC to supply the new field.

## Version 1.3: optional proxy configuration

Set the optional **WEBEX_PROXY_URL** instance field to an HTTP proxy URL,
for example `http://proxy.example.com:8080`. HTTPS requests to Webex use
the proxy's CONNECT tunnel and retain certificate/hostname verification.
This setting is read from instance.conf for every invocation, so event-triggered
runs do not depend on an export in an interactive expert-mode shell.

Leave the field blank to preserve automatic environment/system proxy discovery,
including `https_proxy`. The configured field overrides proxy selection, but
urllib's standard `no_proxy` bypass rules still apply; ensure Webex is not
excluded when a proxy is required. The field supports HTTP proxies without
authentication. Credential-bearing URLs, HTTPS/SOCKS proxy URLs, and URLs with
paths (other than `/`), queries, or fragments are rejected before sending.
An HTTP proxy can carry HTTPS traffic; `http://` describes the connection to
the proxy, not the connection to Webex inside the tunnel.

Install `dist/SendWebexMessage-1.4.tar.gz`, create a version 1.4 instance/action,
and populate its proxy field along with the existing Webex settings. Test it
manually before updating correlation rule responses to use the new action.
The existing version 1.2 archive is retained.

## What was corrected

| Finding | Correction and reason |
| --- | --- |
| Bundled requests 2.34.2 and urllib3 2.7.0 require Python >=3.10. | Replaced requests with Python's built-in urllib, json, and ssl modules, compatible with Python 3.9. |
| The lib directory contains CPython 3.13 Windows extensions, Windows executables, and bytecode caches. | The upload package uses an explicit file allowlist and excludes all of these and the unused Python packages. Original vendor files remain in the checkout for reference. |
| The Python script had no interpreter line. | Added `#!/usr/bin/env python3`. The builder sets Linux executable mode 0755 and LF line endings, even when packaging on Windows. |
| FMC passes the configured remediation name before event fields. The original script displayed that name as OS Vendor and shifted the other values. | Read the action name separately, check its type when present in instance.conf, and map the following three values to vendor, product, and version. |
| OS vendor and product were required. Missing values prevent FMC from launching a remediation. | All three OS fields are optional; absent values are omitted from the message. An alert still sends when none are available. |
| The bot token was a string field; the title was required in the UI despite being optional in code. | Changed the token to a password field and made the title optional. The parser accepts both the new password tag and the old string tag. |
| Every failure returned 129 and raw response bodies were logged. | Added actionable exit codes, safe error messages, TLS verification, redirect rejection, and a dry-run mode. |
| README contained no installation or testing instructions. | Added a reproducible package builder, example configuration, automated tests, and these instructions. |

The original choice to read `instance.conf` from the current working directory
was correct: FMC launches a remediation from that instance's directory. The
script continues to do that. It locates the bundled CA file relative to the
script, so it works regardless of the current directory.

The implementation follows Cisco's documented
[FMC invocation and optional event-field behavior](https://www.cisco.com/c/en/us/td/docs/security/firepower/60/api/remediation/FireSIGHT-System-Remediation-API-Guide/Remediation-SDK.html),
[configuration field and exit-code definitions](https://www.cisco.com/c/en/us/td/docs/security/firepower/60/api/remediation/FireSIGHT-System-Remediation-API-Guide/PackagingClients.html),
and [archive format](https://www.cisco.com/c/en/us/td/docs/security/firepower/60/api/remediation/FireSIGHT-System-Remediation-API-Guide/WritingRemedClients.html).
The [FMC 7.6 administration guide](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/admin/760/management-center-admin-76/correlation-remediations.html)
continues to reference that Remediation API Guide for custom modules.

## Build and install

A ready-to-upload archive is generated at `dist/SendWebexMessage-1.4.tar.gz`,
with a SHA-256 file beside it. To rebuild on a workstation with Python 3.9+:

```sh
python3 build_module.py
```

On Windows, use `python build_module.py` (or the full path to a working
Python executable). Do not zip the project or include an enclosing `module/`
folder. The builder produces this layout:

```text
module.template
send_webex_message.py
lib/cacert.pem
lib/cacert-LICENSE.txt
lib/README.md
```

1. Add your Webex bot to the destination space. Obtain that space's API `id`
   from the Webex Rooms API; a display name or space URL is not the room ID.
   The [Webex Messages API](https://developer.webex.com/messaging/docs/api/v1/messages)
   requires the sender to be a member of the room.
2. In FMC, go to **Policies > Actions > Modules**, choose the archive, and install it.
3. Open the installed module and add an instance, for example `WebexAlerts`.
   Set `WEBEX_TOKEN` to the bot's token (without the `Bearer ` prefix),
   `WEBEX_ROOM_ID` to the API room ID, and optionally `WEBEX_MESSAGE` to a title.
   If a proxy is required, set `WEBEX_PROXY_URL` to `http://your-proxy:port`.
   Enter credentials in FMC, not in module.template or the package.
4. Within that instance, add a remediation of type **Send Webex Message**,
   for example named `NotifyWebex`, and save it.
5. Add that remediation as a response to the intended correlation rule and
   activate the correlation policy. If replacing an older installation, create the
   new instance/action and update the rule response to use version 1.4.
6. Trigger one controlled event. Confirm a message in the space and inspect
   **Analysis > Correlation > Status** (the Remediation Status workflow) for
   the outcome, as described in Cisco's
   [status-event guide](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/admin/760/management-center-admin-76/events-correlation-compliance.html).

The module needs outbound HTTPS access from **FMC** to `webexapis.com:443`,
working DNS, and correct system time. It does not need root privileges.
It honors standard `https_proxy`/`no_proxy` environment settings available
to the remediation process; do not assume FMC's GUI proxy setting is inherited.

## Test before triggering the policy

On your workstation, this uses dummy credentials and makes no network request:

```sh
python3 module/send_webex_message.py --config examples/instance.conf --dry-run NotifyWebex Cisco Linux 9 192.0.2.25
python3 -B -m unittest discover -s tests -v
```

For a dry-run on FMC, enter expert mode and change to the actual installed
instance directory. For the example names above, the documented path is:

```sh
cd /var/sf/remediation/SendWebexMessage_1.4/WebexAlerts
../send_webex_message.py --dry-run NotifyWebex Cisco Linux 9 192.0.2.25; echo "Exit code: $?"
```

Use the directory and action name FMC actually created. The first positional
argument is the **configured action name**, which may differ from the type
`send_webex_message`. Put `--config` and `--dry-run` before that name.
Dry-run validates configuration and loads TLS trust; it does not verify the
token, space membership, network connectivity, or actual API delivery.

To send one manual test message from the same instance directory:

```sh
../send_webex_message.py NotifyWebex Cisco Linux 9 192.0.2.25; echo "Exit code: $?"
```

You can also test missing discovery information with
`../send_webex_message.py NotifyWebex undefined undefined undefined undefined`.
This sends a message containing the title, action name, and
`Source IP: IP-not-identified`, without OS fields. The module does not request
destination addresses or the triggering event description.

## Troubleshooting and limits

| Exit code | Meaning / next check |
| --- | --- |
| 0 | Webex returned HTTP 200 or 201. |
| 2 | Command-line usage error reported by Python's argument parser. |
| 129 | Webex rejected the request or returned an unexpected status. HTTP 404 usually warrants checking the room ID and bot membership. |
| 130 | Missing/invalid instance configuration, wrong action name/type, or too many event arguments. |
| 131 | HTTP 401/403: token or permission problem. |
| 132 | DNS, connection, timeout, or HTTP transport failure. |
| 133 | CA bundle could not load, or TLS validation/handshake failed. |
| 134 | HTTP 429: reduce notification frequency. |

TLS certificate and hostname verification remain enabled. `lib/cacert.pem`
is the Mozilla CA bundle copied from the supplied certifi 2026.7.22 package,
with its license. It supplements the system trust store. For TLS inspection,
ensure the inspection CA is trusted by Python's system trust store or supply
an approved CA file using `SSL_CERT_FILE` in the remediation process environment.
No change to the FMC Python installation is needed.

The HTTP timeout is 15 seconds per blocking operation, not a total wall-clock
deadline. No automatic retry occurs: after a timeout, Webex may already have
accepted the message. Check the space before manually retrying. Separate
correlation triggers each produce their own message; tune the policy's response
frequency if alerts are too frequent.

The token password field controls the UI presentation; it does not imply that
FMC encrypts the value in instance.conf. The script never prints the token or
raw HTTP bodies. Message title and event data are escaped as literal text,
and oversized messages are truncated.

## Review and validation performed

- Version 1.4: all 26 local tests passed, including IPv4/IPv6 text, omitted and undefined source IPs,
  preservation of OS field positions, source IP in the outgoing Webex payload,
  and the updated four-field template and packaged dry-run.
- Version 1.3: all 23 local tests pass, including configured proxy selection,
  legacy configurations without a proxy field, invalid proxy redaction,
  dry-run reporting, and the existing archive/standard-library checks.
  The proxy change still needs live testing on FMC; no Webex messages were sent
  during these local tests.
- Reviewed the project script, template, package layout, bundled dependency
  metadata, relevant library startup requirements, and native/cached artifacts.
- Verified 116 readable vendor files with hashes from their existing wheel
  RECORD manifests; no mismatches were found. This is an integrity check
  against the supplied manifests, not an independent security audit. Windows
  binaries were inventoried, not executed or disassembled.
- The original 19 local tests passed on Python 3.12.14, including mocked Webex success,
  authentication/rate-limit/server failures, timeouts, TLS errors, credential
  redaction, optional fields, and configuration validation.
- Parsed the runtime and builder with Python 3.9 grammar. The packaged script
  also passed a dry-run from an FMC-style instance directory with site-packages
  disabled, proving it does not need the original bundled Python libraries.
- Checked archive member names, LF line endings, executable permissions,
  repeatable archive bytes, and actual CA loading with certificate verification.

An actual Python 3.9.9/FMC 7.6 execution, validation against your appliance's
`/etc/sf/remediation/module.template.xsd`, and live Webex delivery remain for
your test. No real Webex messages were sent during local validation.
