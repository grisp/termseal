#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import os
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = Path(__file__).resolve().parent

CMS_VERIFICATION_DIR = ROOT / "termseal_cms_verification_SUITE_data"
CMS_VERIFICATION_CERTS_DIR = CMS_VERIFICATION_DIR / "certs"
CMS_VERIFICATION_KEYS_DIR = CMS_VERIFICATION_DIR / "keys"
CMS_VERIFICATION_SEALS_DIR = CMS_VERIFICATION_DIR / "seals"

CMS_SEALING_CERTS_DIR = ROOT / "termseal_cms_sealing_SUITE_data" / "certs"
CMS_SEALING_KEYS_DIR = ROOT / "termseal_cms_sealing_SUITE_data" / "keys"

TSF_V1_CERTS_DIR = ROOT / "termseal_tsf_v1_SUITE_data" / "certs"
TSF_V1_KEYS_DIR = ROOT / "termseal_tsf_v1_SUITE_data" / "keys"

LONG_NOT_BEFORE = datetime(2023, 1, 1, tzinfo=timezone.utc)
LONG_NOT_AFTER = datetime(2099, 1, 1, tzinfo=timezone.utc)
EXPIRED_NOT_AFTER = datetime(2024, 6, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class VerificationFixtureSet:
    prefix: str
    root_cn: str
    intermediate_cn: str
    signer_cn: str
    expired_cert: str | None = None


CMS_VERIFICATION_FIXTURE_SETS = [
    VerificationFixtureSet(
        prefix="valid",
        root_cn="Valid CMS Root CA",
        intermediate_cn="Valid CMS Intermediate CA",
        signer_cn="Valid CMS Signer",
    ),
    VerificationFixtureSet(
        prefix="unrelated",
        root_cn="Unrelated CMS Root CA",
        intermediate_cn="Unrelated CMS Intermediate CA",
        signer_cn="Unrelated CMS Signer",
    ),
    VerificationFixtureSet(
        prefix="expired_leaf",
        root_cn="Expired Leaf CMS Root CA",
        intermediate_cn="Expired Leaf CMS Intermediate CA",
        signer_cn="Expired Leaf CMS Signer",
        expired_cert="signer",
    ),
    VerificationFixtureSet(
        prefix="expired_intermediate",
        root_cn="Expired Intermediate CMS Root CA",
        intermediate_cn="Expired Intermediate CMS Intermediate CA",
        signer_cn="Expired Intermediate CMS Signer",
        expired_cert="intermediate",
    ),
    VerificationFixtureSet(
        prefix="expired_root",
        root_cn="Expired Root CMS Root CA",
        intermediate_cn="Expired Root CMS Intermediate CA",
        signer_cn="Expired Root CMS Signer",
        expired_cert="root",
    ),
]


def main() -> None:
    generate_cms_verification_fixtures()
    generate_cms_sealing_certs()
    generate_tsf_v1_certs()


def generate_cms_verification_fixtures() -> None:
    payload_path = extract_signed_payload()

    for fixture_set in CMS_VERIFICATION_FIXTURE_SETS:
        issue_verification_fixture_set(fixture_set)

    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_valid_signed.base64",
        signer_prefix="valid",
        embedded_cert_filenames=[
            "valid_cms_intermediate_ca.crt",
        ],
    )
    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_missing_intermediate_signed.base64",
        signer_prefix="valid",
        embedded_cert_filenames=[],
    )
    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_wrong_chain_signed.base64",
        signer_prefix="valid",
        embedded_cert_filenames=[
            "unrelated_cms_intermediate_ca.crt",
        ],
    )
    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_expired_leaf_signed.base64",
        signer_prefix="expired_leaf",
        embedded_cert_filenames=[
            "expired_leaf_cms_intermediate_ca.crt",
        ],
    )
    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_expired_intermediate_signed.base64",
        signer_prefix="expired_intermediate",
        embedded_cert_filenames=[
            "expired_intermediate_cms_intermediate_ca.crt",
        ],
    )
    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_expired_root_signed.base64",
        signer_prefix="expired_root",
        embedded_cert_filenames=[
            "expired_root_cms_intermediate_ca.crt",
        ],
    )
    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_unordered_chain_with_root_signed.base64",
        signer_prefix="valid",
        embedded_cert_filenames=[
            "valid_cms_root_ca.crt",
            "valid_cms_intermediate_ca.crt",
        ],
    )
    sign_verification_fixture(
        payload_path,
        seal_name="fixture_cms_extra_unrelated_cert_signed.base64",
        signer_prefix="valid",
        embedded_cert_filenames=[
            "unrelated_cms_root_ca.crt",
            "valid_cms_intermediate_ca.crt",
        ],
    )


def generate_cms_sealing_certs() -> None:
    root_key = load_private_key(CMS_SEALING_KEYS_DIR / "cms_root_ca.key")
    intermediate_key = load_private_key(CMS_SEALING_KEYS_DIR / "cms_intermediate_ca.key")
    unrelated_root_key = load_private_key(CMS_SEALING_KEYS_DIR / "cms_unrelated_root_ca.key")
    rsa_signer_key = load_private_key(CMS_SEALING_KEYS_DIR / "cms_rsa_signer.key")
    ec_signer_key = load_private_key(CMS_SEALING_KEYS_DIR / "cms_ec_signer.key")

    root_name = name("CMS Test Root CA", organization="Stritzinger")
    intermediate_name = name("CMS Test Intermediate CA", organization="Stritzinger")
    rsa_signer_name = name("CMS Test Signer", organization="Stritzinger")
    ec_signer_name = name("CMS Test EC Signer", organization="Stritzinger")
    unrelated_root_name = name("CMS Unrelated Root CA", organization="Stritzinger")

    root_cert = build_ca_cert(
        subject=root_name,
        issuer=root_name,
        subject_key=root_key.public_key(),
        issuer_key=root_key,
        serial=1,
        path_length=1,
        not_after=LONG_NOT_AFTER,
    )
    intermediate_cert = build_ca_cert(
        subject=intermediate_name,
        issuer=root_cert.subject,
        subject_key=intermediate_key.public_key(),
        issuer_key=root_key,
        serial=2,
        path_length=0,
        issuer_cert=root_cert,
        not_after=LONG_NOT_AFTER,
    )
    rsa_signer_cert = build_signer_cert(
        subject=rsa_signer_name,
        issuer=intermediate_cert.subject,
        subject_key=rsa_signer_key.public_key(),
        issuer_key=intermediate_key,
        serial=3,
        issuer_cert=intermediate_cert,
        not_after=LONG_NOT_AFTER,
    )
    ec_signer_cert = build_signer_cert(
        subject=ec_signer_name,
        issuer=intermediate_cert.subject,
        subject_key=ec_signer_key.public_key(),
        issuer_key=intermediate_key,
        serial=4,
        issuer_cert=intermediate_cert,
        not_after=LONG_NOT_AFTER,
    )
    unrelated_root_cert = build_ca_cert(
        subject=unrelated_root_name,
        issuer=unrelated_root_name,
        subject_key=unrelated_root_key.public_key(),
        issuer_key=unrelated_root_key,
        serial=5,
        path_length=1,
        not_after=LONG_NOT_AFTER,
    )

    write_cert(CMS_SEALING_CERTS_DIR / "cms_root_ca.crt", root_cert)
    write_cert(CMS_SEALING_CERTS_DIR / "cms_intermediate_ca.crt", intermediate_cert)
    write_cert(CMS_SEALING_CERTS_DIR / "cms_rsa_signer.crt", rsa_signer_cert)
    write_cert(CMS_SEALING_CERTS_DIR / "cms_ec_signer.crt", ec_signer_cert)
    write_cert(CMS_SEALING_CERTS_DIR / "cms_unrelated_root_ca.crt", unrelated_root_cert)


def generate_tsf_v1_certs() -> None:
    rsa_key = load_private_key(TSF_V1_KEYS_DIR / "CA_rsa.key")
    ec_key = load_private_key(TSF_V1_KEYS_DIR / "CA_ec.key")

    common_name = "Test Server Root CA"
    rsa_name = name(common_name)
    ec_name = name(common_name)

    rsa_cert = build_ca_cert(
        subject=rsa_name,
        issuer=rsa_name,
        subject_key=rsa_key.public_key(),
        issuer_key=rsa_key,
        serial=101,
        path_length=0,
        not_after=LONG_NOT_AFTER,
    )
    ec_cert = build_ca_cert(
        subject=ec_name,
        issuer=ec_name,
        subject_key=ec_key.public_key(),
        issuer_key=ec_key,
        serial=102,
        path_length=0,
        not_after=LONG_NOT_AFTER,
    )
    expired_rsa_cert = build_ca_cert(
        subject=rsa_name,
        issuer=rsa_name,
        subject_key=rsa_key.public_key(),
        issuer_key=rsa_key,
        serial=103,
        path_length=0,
        not_after=EXPIRED_NOT_AFTER,
    )
    expired_ec_cert = build_ca_cert(
        subject=ec_name,
        issuer=ec_name,
        subject_key=ec_key.public_key(),
        issuer_key=ec_key,
        serial=104,
        path_length=0,
        not_after=EXPIRED_NOT_AFTER,
    )

    write_cert(TSF_V1_CERTS_DIR / "CA_rsa.crt", rsa_cert)
    write_cert(TSF_V1_CERTS_DIR / "CA_ec.crt", ec_cert)
    write_cert(TSF_V1_CERTS_DIR / "expired_CA_rsa.crt", expired_rsa_cert)
    write_cert(TSF_V1_CERTS_DIR / "expired_CA_ec.crt", expired_ec_cert)


def extract_signed_payload() -> Path:
    source = CMS_VERIFICATION_SEALS_DIR / "fixture_cms_valid_signed.base64"
    decoded = base64.b64decode(source.read_bytes())
    with tempfile.NamedTemporaryFile(delete=False) as temp_input, tempfile.NamedTemporaryFile(
        delete=False
    ) as temp_output:
        temp_input.write(decoded)
        temp_input.flush()
        subprocess.run(
            [
                "openssl",
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-noverify",
                "-binary",
                "-in",
                temp_input.name,
                "-out",
                temp_output.name,
            ],
            check=True,
            capture_output=True,
        )
        return Path(temp_output.name)


def issue_verification_fixture_set(fixture_set: VerificationFixtureSet) -> None:
    root_key = load_private_key(CMS_VERIFICATION_KEYS_DIR / f"{fixture_set.prefix}_cms_root_ca.key")
    intermediate_key = load_private_key(
        CMS_VERIFICATION_KEYS_DIR / f"{fixture_set.prefix}_cms_intermediate_ca.key"
    )
    signer_key = load_private_key(CMS_VERIFICATION_KEYS_DIR / f"{fixture_set.prefix}_cms_signer.key")

    root_cert = build_ca_cert(
        subject=name(fixture_set.root_cn, organization="Stritzinger"),
        issuer=name(fixture_set.root_cn, organization="Stritzinger"),
        subject_key=root_key.public_key(),
        issuer_key=root_key,
        serial=serial_number(fixture_set.prefix, "root"),
        path_length=1,
        not_after=verification_cert_not_after(fixture_set, "root"),
    )
    write_cert(CMS_VERIFICATION_CERTS_DIR / f"{fixture_set.prefix}_cms_root_ca.crt", root_cert)

    intermediate_cert = build_ca_cert(
        subject=name(fixture_set.intermediate_cn, organization="Stritzinger"),
        issuer=root_cert.subject,
        subject_key=intermediate_key.public_key(),
        issuer_key=root_key,
        serial=serial_number(fixture_set.prefix, "intermediate"),
        path_length=0,
        issuer_cert=root_cert,
        not_after=verification_cert_not_after(fixture_set, "intermediate"),
    )
    write_cert(
        CMS_VERIFICATION_CERTS_DIR / f"{fixture_set.prefix}_cms_intermediate_ca.crt",
        intermediate_cert,
    )

    signer_cert = build_signer_cert(
        subject=name(fixture_set.signer_cn, organization="Stritzinger"),
        issuer=intermediate_cert.subject,
        subject_key=signer_key.public_key(),
        issuer_key=intermediate_key,
        issuer_cert=intermediate_cert,
        serial=serial_number(fixture_set.prefix, "signer"),
        not_after=verification_cert_not_after(fixture_set, "signer"),
    )
    write_cert(CMS_VERIFICATION_CERTS_DIR / f"{fixture_set.prefix}_cms_signer.crt", signer_cert)


def verification_cert_not_after(fixture_set: VerificationFixtureSet, cert_kind: str) -> datetime:
    if fixture_set.expired_cert == cert_kind:
        return EXPIRED_NOT_AFTER
    return LONG_NOT_AFTER


def sign_verification_fixture(
    payload_path: Path,
    *,
    seal_name: str,
    signer_prefix: str,
    embedded_cert_filenames: list[str],
) -> None:
    signer_cert = CMS_VERIFICATION_CERTS_DIR / f"{signer_prefix}_cms_signer.crt"
    signer_key = CMS_VERIFICATION_KEYS_DIR / f"{signer_prefix}_cms_signer.key"
    output_der = CMS_VERIFICATION_SEALS_DIR / seal_name.replace(".base64", ".der")
    command = [
        "openssl",
        "cms",
        "-sign",
        "-binary",
        "-nodetach",
        "-md",
        "sha256",
        "-in",
        str(payload_path),
        "-signer",
        str(signer_cert),
        "-inkey",
        str(signer_key),
        "-outform",
        "DER",
        "-out",
        str(output_der),
    ]
    if embedded_cert_filenames:
        cert_bundle_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as cert_bundle:
                cert_bundle_path = cert_bundle.name
                for filename in embedded_cert_filenames:
                    cert_bundle.write((CMS_VERIFICATION_CERTS_DIR / filename).read_bytes())
                cert_bundle.flush()
            command.extend(["-certfile", cert_bundle_path])
            subprocess.run(command, check=True, capture_output=True)
        finally:
            if cert_bundle_path is not None:
                os.unlink(cert_bundle_path)
    else:
        subprocess.run(command, check=True, capture_output=True)
    encoded = base64.encodebytes(output_der.read_bytes())
    (CMS_VERIFICATION_SEALS_DIR / seal_name).write_bytes(encoded)
    output_der.unlink()


def build_ca_cert(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    subject_key,
    issuer_key,
    serial: int,
    path_length: int,
    not_after: datetime,
    issuer_cert: x509.Certificate | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key)
        .serial_number(serial)
        .not_valid_before(LONG_NOT_BEFORE)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def build_signer_cert(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    subject_key,
    issuer_key,
    serial: int,
    issuer_cert: x509.Certificate,
    not_after: datetime,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key)
        .serial_number(serial)
        .not_valid_before(LONG_NOT_BEFORE)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
    )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def serial_number(prefix: str, cert_kind: str) -> int:
    source = f"termseal:{prefix}:{cert_kind}".encode("ascii")
    return int.from_bytes(source[:20].ljust(20, b"\0"), "big") | 1


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def name(common_name: str, organization: str | None = None) -> x509.Name:
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Barcelona"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Barcelona"),
    ]
    if organization is not None:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


if __name__ == "__main__":
    main()
