"""Verify one release against the trusted source checkout. Never extract archive paths."""

import base64
import configparser
import csv
import hashlib
import io
import re
import stat
import sys
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
NAME = PROJECT["name"].replace("-", "_")
VERSION = PROJECT["version"]
RELEASE = f"{NAME}-{VERSION}"
INFO = RELEASE + ".dist-info/"
MODULES = set(
    """__init__ __main__ client credentials handshake pki proxy security server service trust wire""".split()
)
WHEEL_SOURCE = {f"{NAME}/{m}.py": f"src/{NAME}/{m}.py" for m in MODULES}
WHEEL_SOURCE[INFO + "licenses/LICENSE"] = "LICENSE"
META = {"METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt"}
EGG = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
}
SOURCES = set(WHEEL_SOURCE.values()) | {
    "README.md",
    "LICENSE",
    "MANIFEST.in",
    "pyproject.toml",
    "docs/protocol.md",
    "docs/security.md",
    "requirements/runtime.lock",
    "requirements/build.lock",
    "requirements/build.in",
    "tools/verify_dist.py",
    "tests/test_cli.py",
    "tests/test_runtime.py",
    "tests/test_security.py",
    "tests/test_distribution.py",
    "tests/test_hardening.py",
}
WHEEL_FILES = set(WHEEL_SOURCE) | {INFO + n for n in META}
SOURCE_FILES = {RELEASE + "/" + f for f in SOURCES | {"setup.cfg", "PKG-INFO"}}
SOURCE_FILES |= {f"{RELEASE}/src/{NAME}.egg-info/{f}" for f in EGG}
PRIVATE_PEM = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
MAX_MEMBER = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def check_member(name, data, wheel):
    permitted = WHEEL_FILES if wheel else SOURCE_FILES
    if name not in permitted or PRIVATE_PEM.search(data):
        raise ValueError(f"unexpected member or private key in {name}")


def members(path, wheel):
    expected = WHEEL_FILES if wheel else SOURCE_FILES
    contents = {}
    total = 0

    def read(name, size, stream):
        nonlocal total
        total += size
        if (
            name not in expected
            or name in contents
            or size < 0
            or size > MAX_MEMBER
            or total > MAX_TOTAL
        ):
            raise ValueError(f"invalid member, duplicate, or size: {name}")
        with stream() as opened:
            data = opened.read(size + 1)
        if len(data) != size:
            raise ValueError(f"size mismatch: {name}")
        check_member(name, data, wheel)
        contents[name] = data

    if wheel:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > len(expected):
                raise ValueError("too many wheel members")
            for info in archive.infolist():
                if stat.S_IFMT(info.external_attr >> 16) not in {0, stat.S_IFREG}:
                    raise ValueError("unexpected wheel file type")
                read(info.filename, info.file_size, lambda: archive.open(info))
    else:
        dirs = {str(parent) for n in expected for parent in PurePosixPath(n).parents}
        seen_dirs = set()
        with tarfile.open(path, "r|gz") as archive:
            for item in archive:
                if item.isdir() and item.name in dirs and item.name not in seen_dirs:
                    seen_dirs.add(item.name)
                elif item.type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                    read(item.name, item.size, lambda: archive.extractfile(item))
                else:
                    raise ValueError(
                        f"unexpected directory, link or special file: {item.name}"
                    )
    if contents.keys() != expected:
        raise ValueError(f"missing members: {sorted(expected - contents.keys())}")
    return contents


def verify_record(files):
    record = INFO + "RECORD"
    seen = set()
    for name, digest, size in csv.reader(io.StringIO(files[record].decode("utf-8"))):
        if name in seen or name not in files:
            raise ValueError("duplicate or unexpected RECORD entry")
        seen.add(name)
        data = files[name]
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        )
        expected_fields = (
            ("", "") if name == record else ("sha256=" + expected, str(len(data)))
        )
        if (digest, size) != expected_fields:
            raise ValueError(f"RECORD mismatch: {name}")
    if seen != files.keys():
        raise ValueError("incomplete wheel RECORD")


def _compare(data, source):
    # Source checkouts on Windows may use CRLF. RECORD always covers the exact wheel bytes.
    if data.replace(b"\r\n", b"\n") != (ROOT / source).read_bytes().replace(
        b"\r\n", b"\n"
    ):
        raise ValueError(f"content differs from trusted source: {source}")


def _metadata(data):
    fields = BytesParser().parsebytes(data)
    for key, value in (
        ("Name", PROJECT["name"]),
        ("Version", VERSION),
        ("Requires-Python", PROJECT["requires-python"]),
    ):
        if fields.get_all(key) != [value]:
            raise ValueError(f"release metadata mismatch: {key}")
    if sorted(fields.get_all("Requires-Dist", [])) != sorted(PROJECT["dependencies"]):
        raise ValueError("release dependencies differ from pyproject.toml")


def _entry_points(data):
    entries = configparser.ConfigParser(interpolation=None)
    entries.optionxform = str
    entries.read_string(data.decode())
    if (
        entries.sections() != ["console_scripts"]
        or dict(entries["console_scripts"]) != PROJECT["scripts"]
    ):
        raise ValueError("entry points differ from pyproject.toml")


def verify(directory):
    directory = Path(directory)
    wheel = directory / f"{RELEASE}-py3-none-any.whl"
    source = directory / f"{RELEASE}.tar.gz"
    if set(directory.iterdir()) != {wheel, source}:
        raise ValueError(f"expected exactly the source and wheel for {RELEASE}")
    wf = members(wheel, True)
    verify_record(wf)
    wheel_info = BytesParser().parsebytes(wf[INFO + "WHEEL"])
    if (
        wheel_info.get_all("Tag") != ["py3-none-any"]
        or wheel_info.get_all("Root-Is-Purelib") != ["true"]
        or wheel_info.get_all("Wheel-Version") != ["1.0"]
    ):
        raise ValueError("unexpected wheel compatibility or installation layout")
    if wf[INFO + "top_level.txt"].decode().splitlines() != [NAME]:
        raise ValueError("unexpected wheel top-level package")
    for name, path in WHEEL_SOURCE.items():
        _compare(wf[name], path)
    _metadata(wf[INFO + "METADATA"])
    _entry_points(wf[INFO + "entry_points.txt"])
    sf = members(source, False)
    generated_cfg = configparser.ConfigParser(interpolation=None)
    generated_cfg.read_string(sf[f"{RELEASE}/setup.cfg"].decode())
    if (
        generated_cfg.defaults()
        or generated_cfg.sections() != ["egg_info"]
        or dict(generated_cfg["egg_info"]) != {"tag_build": "", "tag_date": "0"}
    ):
        raise ValueError("unexpected generated build configuration")
    for path in SOURCES:
        _compare(sf[f"{RELEASE}/{path}"], path)
    _metadata(sf[f"{RELEASE}/PKG-INFO"])
    _metadata(sf[f"{RELEASE}/src/{NAME}.egg-info/PKG-INFO"])
    _entry_points(sf[f"{RELEASE}/src/{NAME}.egg-info/entry_points.txt"])
    for artifact in (wheel, source):
        print(hashlib.sha256(artifact.read_bytes()).hexdigest(), artifact.name)


if __name__ == "__main__":
    verify(sys.argv[1] if len(sys.argv) == 2 else "dist")
