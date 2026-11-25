"""Check wheel and source distribution contents without extracting files to disk."""

import re
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MODULES = {
    "__init__.py",
    "__main__.py",
    "client.py",
    "server.py",
    "credentials.py",
    "handshake.py",
    "pki.py",
    "proxy.py",
    "security.py",
    "service.py",
    "wire.py",
}
METADATA = {
    "METADATA",
    "WHEEL",
    "RECORD",
    "entry_points.txt",
    "top_level.txt",
    "licenses/LICENSE",
}
EGG_INFO = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
}
SOURCES = {
    "LICENSE",
    "README.md",
    "MANIFEST.in",
    "pyproject.toml",
    "PKG-INFO",
    "setup.cfg",
    "docs/protocol.md",
    "docs/security.md",
    "tools/verify_dist.py",
    "tests/test_security.py",
    "tests/test_runtime.py",
    "tests/test_distribution.py",
    "tests/test_cli.py",
}
PRIVATE_PEM = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


def check_member(name, data, wheel):
    parts = PurePosixPath(name).parts
    if not parts or name.startswith("/") or "\\" in name or ".." in parts:
        raise ValueError(f"unsafe member path: {name}")
    if wheel:
        package_file = (
            len(parts) == 2 and parts[0] == "sovereign_chain" and parts[1] in MODULES
        )
        metadata = parts[0].startswith("sovereign_chain-") and parts[0].endswith(
            ".dist-info"
        )
        permitted = package_file or (metadata and "/".join(parts[1:]) in METADATA)
    else:
        path = "/".join(parts[1:])
        permitted = (
            path in SOURCES
            or (
                len(parts) == 4
                and parts[1:3] == ("src", "sovereign_chain")
                and parts[3] in MODULES
            )
            or (
                len(parts) == 4
                and parts[1:3] == ("src", "sovereign_chain.egg-info")
                and parts[3] in EGG_INFO
            )
        )
        permitted = permitted and parts[0].startswith("sovereign_chain-")
    if not permitted or PRIVATE_PEM.search(data):
        raise ValueError(
            f"prohibited distribution member or private key content: {name}"
        )


def verify(directory):
    paths = sorted(Path(directory).iterdir())
    if not any(p.suffix == ".whl" for p in paths) or not any(
        p.name.endswith(".tar.gz") for p in paths
    ):
        raise ValueError("expected both a wheel and a source distribution")
    for path in paths:
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if not member.is_dir():
                        check_member(member.filename, archive.read(member), True)
        elif path.name.endswith(".tar.gz"):
            with tarfile.open(path, "r:gz") as archive:
                for item in archive:
                    if item.isdir():
                        continue
                    if not item.isfile():
                        raise ValueError(
                            f"unexpected link or special file: {item.name}"
                        )
                    with archive.extractfile(item) as stream:
                        check_member(item.name, stream.read(), False)
        else:
            raise ValueError(f"unexpected release artifact: {path.name}")
        print("Verified", path.name)


if __name__ == "__main__":
    verify(sys.argv[1] if len(sys.argv) == 2 else "dist")
