#!/usr/bin/env python3
"""Build the FMC upload archive on Windows or Linux; no pip packages required."""

import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "module"
# Deliberate allowlist: never package instance credentials, caches, or Windows wheels.
FILES = ("module.template", "send_webex_message.py", "lib/cacert.pem",
         "lib/cacert-LICENSE.txt", "lib/README.md")


def build_package(output_dir=None):
    template = ET.parse(str(MODULE / "module.template")).getroot()
    version = template.findtext("global_config/version")
    output_dir = Path(output_dir) if output_dir else ROOT / "dist"
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / ("SendWebexMessage-" + version + ".tar.gz")
    with target.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                directory = tarfile.TarInfo("lib")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                archive.addfile(directory)
                for name in FILES:
                    data = (MODULE / name).read_bytes().replace(b"\r\n", b"\n")
                    info = tarfile.TarInfo(name)
                    info.mode = 0o755 if name == "send_webex_message.py" else 0o644
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(target.suffix + ".sha256").write_text(
        digest + "  " + target.name + "\n", encoding="ascii")
    return target


if __name__ == "__main__":
    print(build_package())
