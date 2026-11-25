"""Deployments snapshot related credential files together before admitting sessions."""

import datetime
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .trust import (
    UTC,
    Revocations,
    parse_crl,
    read_crl,
    require_crl_setting,
    validate_ca_certificate,
    validate_peer_certificate,
    verify_private_key_matches_certificate,
)

SERVER_NAME = "Sovereign-Chain-Server"
CLIENT_NAME = "Sovereign-Chain-Client"
logger = logging.getLogger(__name__)


def pki_directory():
    return Path(
        os.getenv("SC_PKI_DIR") or Path.home() / ".sovereign-chain" / "pki"
    ).expanduser()


def role_file(role, variable, filename):
    return Path(os.getenv(variable) or pki_directory() / role / filename).expanduser()


def load_certificate(role, ca=False):
    name = "ca" if ca else role
    return x509.load_pem_x509_certificate(
        role_file(role, f"SC_{name.upper()}_CERT_FILE", f"{name}_cert.pem").read_bytes()
    )


def load_key(role):
    path = role_file(role, f"SC_{role.upper()}_KEY_FILE", f"{role}_key.pem")
    return _decode_key(path.read_bytes(), os.getenv(f"SC_{role.upper()}_KEY_PASSWORD"))


def _decode_key(data, password):
    key = serialization.load_pem_private_key(
        data, password.encode() if password else None
    )
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("SC-EE-3 requires Ed25519 endpoint keys")
    return key


@dataclass(frozen=True)
class Identity:
    key: ed25519.Ed25519PrivateKey
    cert: x509.Certificate
    anchor: x509.Certificate
    revocations: Revocations | None

    def expires(self):
        dates = [self.cert.not_valid_after_utc, self.anchor.not_valid_after_utc]
        if self.revocations is not None:
            dates.append(self.revocations.until)
        return min(dates)


class CredentialStore:
    """A validated snapshot. Changed or invalid files invalidate the previous generation."""

    def __init__(self, role, *, ingress_dir=None):
        self.role = role
        prefix = "SC_INGRESS_" if ingress_dir is not None else "SC_"
        directory = (
            Path(ingress_dir).expanduser()
            if ingress_dir is not None
            else pki_directory()
        ) / role
        self.key_path = Path(
            os.getenv(prefix + role.upper() + "_KEY_FILE")
            or directory / f"{role}_key.pem"
        ).expanduser()
        self.cert_path = Path(
            os.getenv(prefix + role.upper() + "_CERT_FILE")
            or directory / f"{role}_cert.pem"
        ).expanduser()
        self.ca_path = Path(
            os.getenv(prefix + "CA_CERT_FILE") or directory / "ca_cert.pem"
        ).expanduser()
        path = os.getenv(prefix + "CRL_FILE")
        if require_crl_setting(prefix + "REQUIRE_CRL") and not path:
            raise ValueError(f"{prefix}CRL_FILE is required")
        self.crl_path = Path(path).expanduser() if path else None
        self.paths = [self.key_path, self.cert_path, self.ca_path]
        if self.crl_path:
            self.paths.append(self.crl_path)
        self.password = os.getenv(prefix + role.upper() + "_KEY_PASSWORD")
        self.server_name = os.getenv(prefix + "SERVER_NAME", SERVER_NAME)
        self._lock = threading.Lock()
        self._last_crl = None
        self._stamp = None
        self._value = None
        self._error = "credentials have not been loaded"

    def _file_stamp(self):
        result = []
        for path in self.paths:
            stat = path.stat()
            result.append(
                (
                    stat.st_dev,
                    stat.st_ino,
                    stat.st_size,
                    stat.st_mtime_ns,
                    stat.st_ctime_ns,
                )
            )
        return tuple(result)

    def _load(self):
        if any(p.stat().st_size > 1_000_000 for p in self.paths[:3]):
            raise ValueError("credential file exceeds size limit")
        key = _decode_key(self.key_path.read_bytes(), self.password)
        cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        anchor = x509.load_pem_x509_certificate(self.ca_path.read_bytes())
        validate_ca_certificate(anchor)
        verify_private_key_matches_certificate(key, cert)
        now = datetime.datetime.now(UTC)
        crl = parse_crl(read_crl(self.crl_path), anchor) if self.crl_path else None
        if crl and not crl.since <= now < crl.until:
            raise ValueError("CRL outside its validity period")
        if self.role == "server":
            validate_peer_certificate(
                cert, anchor, "server", self.server_name, now, revocations=crl
            )
        elif not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError("client certificate outside its validity period")
        return Identity(key, cert, anchor, crl)

    def refresh(self):
        """Return true when sessions using the preceding snapshot must be retired."""
        with self._lock:
            previous = self._value
            try:
                stamp = self._file_stamp()
                if (
                    stamp == self._stamp
                    and previous
                    and previous.expires() > datetime.datetime.now(UTC)
                ):
                    return False
                candidate = self._load()
                if self._file_stamp() != stamp:
                    raise ValueError("credential files changed during reload")
                old, new = self._last_crl, candidate.revocations
                if old and new and old.authority == new.authority:
                    older_number = old.number is not None and (
                        new.number is None or new.number < old.number
                    )
                    if older_number or new.since < old.since:
                        raise ValueError("CRL rollback refused")
                self._last_crl = new
                self._value, self._stamp, self._error = candidate, stamp, None
                return True
            except (
                OSError,
                ValueError,
                TypeError,
                UnsupportedAlgorithm,
                x509.DuplicateExtension,
            ) as exc:
                detail = f"{type(exc).__name__}: {exc}"
                if detail != self._error:
                    logger.error("%s credentials unavailable: %s", self.role, detail)
                self._value, self._stamp, self._error = None, None, detail
                return previous is not None

    @property
    def available(self):
        with self._lock:
            return self._value is not None

    def current(self):
        with self._lock:
            if self._value is None:
                raise ValueError(self._error)
            return self._value


def server_credentials():
    store = CredentialStore("server")
    store.refresh()
    identity = store.current()
    return identity.key, identity.cert, identity.anchor
