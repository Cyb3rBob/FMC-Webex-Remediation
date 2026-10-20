#!/usr/bin/env python3
"""Send an FMC remediation notification using only the Python 3 standard library."""

import argparse
import html
import http.client
import json
import os
import socket
import ssl
import sys
import xml.etree.ElementTree as ET
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CA_FILE = os.path.join(SCRIPT_DIR, "lib", "cacert.pem")
WEBEX_URL = "https://webexapis.com/v1/messages"
TIMEOUT = 15
REMEDIATION_TYPE = "send_webex_message"
EVENT_LABELS = ("OS Vendor", "OS Product", "OS Version", "Source IP")
MISSING_VALUES = ("", "undefined", "null", "(null)")

EXIT_SUCCESS = 0
EXIT_FAILURE = 129
EXIT_CONFIG = 130
EXIT_AUTH = 131
EXIT_NETWORK = 132
EXIT_TLS = 133
EXIT_RATE_LIMIT = 134


class ConfigError(Exception):
    """Invalid local configuration; no request should be made."""


class NoRedirects(HTTPRedirectHandler):
    """Do not forward a bot credential to a redirected endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_instance_config(config_file, remediation_name):
    """FMC runs in the instance directory; configuration is NOT beside this script."""
    try:
        root = ET.parse(config_file).getroot()
    except (OSError, ET.ParseError):
        raise ConfigError("Cannot read instance.conf or its XML is invalid. "
                          "Run from the FMC instance directory or use --config PATH.")
    config = root.find("config")
    if root.tag != "instance" or config is None:
        raise ConfigError("Expected <instance><config> in instance.conf.")

    # Read only instance-level settings, not unrelated remediation settings.
    values = {}
    for elem in config:
        if elem.tag in ("string", "password"):
            name = elem.get("name")
            if name in values:
                raise ConfigError("Duplicate instance configuration field.")
            values[name] = (elem.text or "").strip()
    token = values.get("WEBEX_TOKEN", "")
    room_id = values.get("WEBEX_ROOM_ID", "")
    if not token or not room_id:
        raise ConfigError("WEBEX_TOKEN and WEBEX_ROOM_ID must both be configured.")
    if any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise ConfigError("WEBEX_TOKEN must contain only printable ASCII without spaces.")
    if any(char.isspace() for char in room_id):
        raise ConfigError("WEBEX_ROOM_ID must be the room ID returned by the Webex API.")

    # The first argument is the configured action NAME, not its type or an OS field.
    remediations = root.findall("remediation")
    if remediations:
        matches = [item for item in remediations if item.get("name") == remediation_name]
        if len(matches) != 1 or matches[0].get("type") != REMEDIATION_TYPE:
            raise ConfigError("The remediation name does not match a send_webex_message "
                              "action in instance.conf.")
    # Cisco permits no remediation elements when no per-action config is required.
    proxy_url = values.get("WEBEX_PROXY_URL", "")
    if proxy_url:
        try:
            proxy = urlsplit(proxy_url)
            valid = (proxy.scheme == "http" and proxy.hostname and
                     proxy.username is None and proxy.password is None and
                     proxy.path in ("", "/") and not proxy.query and
                     not proxy.fragment and proxy.port != 0 and
                     not any(char.isspace() or ord(char) < 32 or ord(char) == 127
                             for char in proxy_url))
        except ValueError:
            valid = False
        if not valid:
            raise ConfigError("WEBEX_PROXY_URL must be an HTTP proxy URL such as "
                              "http://proxy.example.com:8080, without credentials, "
                              "a query, or a fragment.")
    return token, room_id, values.get("WEBEX_MESSAGE", ""), proxy_url


def markdown_value(value):
    """Render configured/event text literally, including Webex mention markup."""
    value = " ".join(value.split())
    value = html.escape(value, quote=False)
    for char in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", "!", "|"):
        value = value.replace(char, "\\" + char)
    return value


def build_message(title, remediation_name, event_values):
    title = title or "Cisco FMC Correlation Event Remediation Triggered"
    lines = ["### " + markdown_value(title),
             "", "**Remediation:** " + markdown_value(remediation_name)]
    # Append src_ip_addr in the template to preserve the original OS positions.
    source_ip = event_values[3].strip() if len(event_values) > 3 else ""
    if source_ip.lower() in MISSING_VALUES:
        source_ip = "IP-not-identified"
    lines.append("- **Source IP:** " + markdown_value(source_ip))
    for label, value in zip(EVENT_LABELS[:3], event_values[:3]):
        if value.strip().lower() in MISSING_VALUES:
            continue
        lines.append("- **{}:** {}".format(label, markdown_value(value)))
    message = "\n".join(lines)
    # Leave headroom below the Webex message limit, including multi-byte text.
    encoded = message.encode("utf-8")
    if len(encoded) > 6000:
        message = encoded[:5900].decode("utf-8", errors="ignore") + "\n[Message truncated]"
    return message


def create_tls_context():
    # Keep the OS trust store (including local enterprise roots), and add our bundle.
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=CA_FILE)
    return context


def report(message, code):
    print(message, file=sys.stderr)
    return code


def send_webex_message(webex_token, webex_room_id, text_message, context, proxy_url=""):
    payload = json.dumps({"roomId": webex_room_id, "markdown": text_message}).encode("utf-8")
    request = Request(WEBEX_URL, data=payload, headers={
        "Authorization": "Bearer " + webex_token,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }, method="POST")
    # A configured proxy overrides environment proxy selection. With no setting,
    # urllib retains its normal environment/system proxy discovery behavior.
    handlers = [HTTPSHandler(context=context), NoRedirects()]
    if proxy_url:
        handlers.append(ProxyHandler({"https": proxy_url}))
    opener = build_opener(*handlers)
    try:
        # A single attempt: a timeout may occur AFTER Webex accepts the message.
        with opener.open(request, timeout=TIMEOUT) as response:
            status = response.getcode()
            if status not in (200, 201):
                return report("Unexpected Webex HTTP status {}.".format(status), EXIT_FAILURE)
        print("Webex message sent successfully.")
        return EXIT_SUCCESS
    except HTTPError as error:
        status = error.code
        error.close()
        # Do not log raw response bodies or request headers, which can contain secrets.
        if status == 407:
            return report("Proxy HTTP 407: proxy authentication is required. "
                          "The configured proxy field does not support credentials.", EXIT_NETWORK)
        if status in (401, 403):
            return report("Webex HTTP {}: check the bot token and permission to post "
                          "to this space.".format(status), EXIT_AUTH)
        if status == 404:
            return report("Webex HTTP 404: check the API room ID and add the bot "
                          "to that space.", EXIT_FAILURE)
        if status == 429:
            return report("Webex HTTP 429: rate limited. Reduce the correlation policy "
                          "notification frequency.", EXIT_RATE_LIMIT)
        return report("Webex HTTP {}: message was not accepted; check the configuration "
                      "and Webex service status.".format(status), EXIT_FAILURE)
    except (URLError, OSError, http.client.HTTPException) as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, ssl.SSLError):
            return report("TLS validation/handshake failed. Check FMC time, CA trust, "
                          "TLS inspection, and Python/OpenSSL support.", EXIT_TLS)
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return report("Webex request timed out. Delivery is uncertain; check the "
                          "space before retrying.", EXIT_NETWORK)
        return report("Cannot contact Webex. Check FMC DNS, HTTPS egress, and proxy "
                      "settings. Delivery may be uncertain.", EXIT_NETWORK)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="instance.conf", help="FMC instance XML path")
    parser.add_argument("--dry-run", action="store_true", help="Validate and show message without sending")
    parser.add_argument("remediation_name", help="Configured remediation action name passed by FMC")
    parser.add_argument("event_values", nargs=argparse.REMAINDER, help="OS vendor, product, version, source IP, in template order")
    args = parser.parse_args(argv)
    if len(args.event_values) > len(EVENT_LABELS):
        return report("Too many event fields. Use the module.template shipped with this script.", EXIT_CONFIG)
    try:
        token, room_id, title, proxy_url = parse_instance_config(args.config, args.remediation_name)
    except ConfigError as error:
        return report(str(error), EXIT_CONFIG)
    try:
        context = create_tls_context()
    except (OSError, ValueError):
        return report("Cannot load TLS trust. Include lib/cacert.pem in the package "
                      "and check the system CA configuration.", EXIT_TLS)
    message = build_message(title, args.remediation_name, args.event_values)
    if args.dry_run:
        # ASCII escaping also makes this usable on an appliance with a C locale.
        print("Dry run: configuration and CA bundle loaded; no message sent.")
        print("Proxy: {}.".format("configured HTTP proxy" if proxy_url else
                                  "automatic environment/system settings"))
        print(json.dumps({"markdown": message}, ensure_ascii=True, indent=2))
        return EXIT_SUCCESS
    return send_webex_message(token, room_id, message, context, proxy_url)


if __name__ == "__main__":
    sys.exit(main())


