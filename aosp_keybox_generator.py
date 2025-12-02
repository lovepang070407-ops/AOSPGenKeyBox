#!/usr/bin/env python3
"""
AOSP-like Keybox Generator with ASN.1 KeyDescription Extension
Generates Android Keystore attestation keyboxes following AOSP structure.
"""

import os
import sys
import traceback
import subprocess
import shutil
from random import randint, choice
from datetime import datetime, timezone
from typing import List

try:
    os.chdir(os.path.abspath(os.path.dirname(__file__)))
except Exception:
    pass

try:
    from pyasn1.type import univ, namedtype, constraint
    from pyasn1.codec.der import encoder
    ASN1_AVAILABLE = True
except ImportError:
    ASN1_AVAILABLE = False

try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = -1

LB = 2
UB = 12
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

CHAIN_LENGTH = 3
ATTESTATION_VERSION = 4
KEYMASTER_VERSION = 4
ATTESTATION_SECURITY_LEVEL = 0
KEYMASTER_SECURITY_LEVEL = 0

AOSP_ROOT_SUBJ = "/CN=AOSP Test Attestation Root/O=Android Open Source Project/C=US"
AOSP_INT_SUBJ = "/CN=AOSP Test OEM Attestation CA/O=Android Open Source Project/C=US"
AOSP_LEAF_SUBJ_EC = "/CN=AOSP Test Keystore Attestation Key EC/O=Android Open Source Project/C=US"
AOSP_LEAF_SUBJ_RSA = "/CN=AOSP Test Keystore Attestation Key RSA/O=Android Open Source Project/C=US"

keyboxFormatter = """<?xml version="1.0"?>
<AndroidAttestation>
<NumberOfKeyboxes>1</NumberOfKeyboxes>
<Keybox DeviceID="{device_id}">
<Key algorithm="ecdsa">
<PrivateKey format="pem">
{ec_priv}</PrivateKey>
<CertificateChain>
<NumberOfCertificates>{count}</NumberOfCertificates>
{ec_chain}
</CertificateChain>
</Key>
<Key algorithm="rsa">
<PrivateKey format="pem">
{rsa_priv}</PrivateKey>
<CertificateChain>
<NumberOfCertificates>{count}</NumberOfCertificates>
{rsa_chain}
</CertificateChain>
</Key>
</Keybox>
</AndroidAttestation>
"""

LOG_FILE = None
LOG_BUFFER = []


class AuthorizationList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "purpose",
            univ.Set().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, 32)
            ),
        ),
        namedtype.OptionalNamedType("algorithm", univ.Integer()),
        namedtype.OptionalNamedType("keySize", univ.Integer()),
        namedtype.OptionalNamedType(
            "digest",
            univ.Set().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, 8)
            ),
        ),
        namedtype.OptionalNamedType(
            "padding",
            univ.Set().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, 8)
            ),
        ),
        namedtype.OptionalNamedType("ecCurve", univ.Integer()),
        namedtype.OptionalNamedType("rsaPublicExponent", univ.Integer()),
        namedtype.OptionalNamedType("rollbackResistance", univ.Boolean()),
        namedtype.OptionalNamedType("rootOfTrust", univ.OctetString()),
    )


class KeyDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestationVersion", univ.Integer()),
        namedtype.NamedType("attestationSecurityLevel", univ.Integer()),
        namedtype.NamedType("keymasterVersion", univ.Integer()),
        namedtype.NamedType("keymasterSecurityLevel", univ.Integer()),
        namedtype.NamedType("attestationChallenge", univ.OctetString()),
        namedtype.NamedType("uniqueId", univ.OctetString()),
        namedtype.NamedType("softwareEnforced", AuthorizationList()),
        namedtype.NamedType("teeEnforced", AuthorizationList()),
    )


def run(cmd: str, silent: bool = False) -> int:
    log(f"Executing: {cmd}", console=False)
    if not silent:
        cmd_parts = cmd.split()
        if "openssl" in cmd_parts:
            cmd_type = cmd_parts[1] if len(cmd_parts) > 1 else "command"
            print(f"[EXEC] openssl {cmd_type}...", end="", flush=True)
    try:
        result = os.system(cmd + " > /dev/null 2>&1" if silent else cmd)
        if not silent and "openssl" in cmd:
            print(" done" if result == 0 else " failed")
        log(f"Command result: {result}", console=False)
        return result
    except Exception as e:
        log_exception(e, "run")
        if not silent and "openssl" in cmd:
            print(" failed")
        return 1


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        log(f"Read file: {path}", console=False)
        return content
    except Exception as e:
        log_exception(e, f"read_text({path})")
        raise


def write_text(path: str, content: str) -> None:
    try:
        parent = os.path.dirname(path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        log(f"Wrote file: {path}", console=False)
    except Exception as e:
        log_exception(e, f"write_text({path})")
        raise


def format_chain_xml(certs: List[str]) -> str:
    return "".join(
        f'<Certificate format="pem">\n{c}\n</Certificate>\n' for c in certs
    ).rstrip()


def cleanup_intermediate_files(output_folder: str) -> bool:
    essential_files = [
        "ecPrivateKey.pem",
        "rsaPrivateKey.pem",
        "ecCert_1.pem",
        "ecCert_2.pem",
        "ecCert_3.pem",
        "rsaCert_1.pem",
        "rsaCert_2.pem",
        "rsaCert_3.pem",
        "keybox.xml",
        "generation.log",
        "openssl_aosp.cnf",
    ]

    cleaned_count = 0
    try:
        for item in os.listdir(output_folder):
            item_path = os.path.join(output_folder, item)
            if item not in essential_files:
                if os.path.isfile(item_path):
                    os.remove(item_path)
                    log(f"Cleaned: {item}", console=False)
                    cleaned_count += 1
                elif os.path.isdir(item_path) and item == "newcerts":
                    shutil.rmtree(item_path)
                    os.makedirs(item_path, exist_ok=True)
                    log(
                        "Cleaned & recreated empty newcerts directory",
                        console=False,
                    )
                    cleaned_count += 1

        log(
            f"Cleanup completed: {cleaned_count} intermediate files/directories removed",
            level="OK",
            console=False,
        )
        print(
            f"[CLEAN] {cleaned_count} intermediates removed from "
            f"{os.path.basename(output_folder)}"
        )
        return True
    except Exception as e:
        log_exception(e, "cleanup_intermediate_files")
        return False


def init_logging(output_folder: str) -> None:
    global LOG_FILE
    log_path = os.path.join(output_folder, "generation.log")
    try:
        LOG_FILE = open(log_path, "w", encoding="utf-8")
        for msg in LOG_BUFFER:
            LOG_FILE.write(msg + "\n")
        LOG_BUFFER.clear()
        log(f"Log file initialized: {os.path.abspath(log_path)}")
    except Exception as e:
        print(f"[WARN] Could not create log file: {e}")


def log(message: str, level: str = "INFO", console: bool = True) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    log_entry = f"[{timestamp}] [{level}] {message}"

    if console:
        if level == "ERROR":
            print(f"[ERROR] {message}")
        elif level == "WARN":
            print(f"[WARN] {message}")
        elif level == "INFO":
            print(f"[INFO] {message}")
        elif level == "OK":
            print(f"[OK] {message}")
        else:
            print(message)

    if LOG_FILE and not LOG_FILE.closed:
        try:
            LOG_FILE.write(log_entry + "\n")
            LOG_FILE.flush()
        except Exception:
            pass
    else:
        LOG_BUFFER.append(log_entry)


def log_exception(e: Exception, context: str = "") -> None:
    error_msg = (
        f"Exception in {context}: {str(e)}"
        if context
        else f"Exception: {str(e)}"
    )
    log(error_msg, level="ERROR")
    if LOG_FILE and not LOG_FILE.closed:
        try:
            LOG_FILE.write("\n--- Full Traceback ---\n")
            traceback.print_exc(file=LOG_FILE)
            LOG_FILE.write("--- End Traceback ---\n\n")
            LOG_FILE.flush()
        except Exception:
            pass


def close_logging() -> None:
    global LOG_FILE
    if LOG_FILE and not LOG_FILE.closed:
        try:
            log("Log file closed", console=False)
            LOG_FILE.close()
        except Exception:
            pass


def create_timestamped_folder(chain_length: int) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-UTC")
    folder_name = f"{timestamp}-aosp-chain{chain_length}"
    folder_path = os.path.join(os.getcwd(), folder_name)
    try:
        os.makedirs(folder_path, exist_ok=True)
        log(f"Output folder: {folder_name}")
        return folder_path
    except Exception as e:
        log_exception(e, "create_timestamped_folder")
        return os.getcwd()


def validate_xml(xml_content: str) -> bool:
    if not LXML_AVAILABLE:
        log("XML validation skipped (lxml not available)", console=False)
        return True
    try:
        etree.fromstring(xml_content.encode("utf-8"))
        log("XML validation passed", console=False)
        return True
    except etree.XMLSyntaxError as e:
        log(f"XML validation failed: {e}", level="ERROR")
        return False
    except Exception as e:
        log(f"XML validation error: {e}", level="ERROR")
        return False


def create_keydescription_asn1() -> bytes:
    if not ASN1_AVAILABLE:
        log(
            "pyasn1 not available, KeyDescription empty",
            level="WARN",
            console=False,
        )
        return b""

    try:
        software = AuthorizationList()
        software["algorithm"] = 3
        software["keySize"] = 256
        software["ecCurve"] = 1

        tee = AuthorizationList()

        kd = KeyDescription()
        kd["attestationVersion"] = ATTESTATION_VERSION
        kd["attestationSecurityLevel"] = ATTESTATION_SECURITY_LEVEL
        kd["keymasterVersion"] = KEYMASTER_VERSION
        kd["keymasterSecurityLevel"] = KEYMASTER_SECURITY_LEVEL
        kd["attestationChallenge"] = b"AOSP-TEST-CHALLENGE"
        kd["uniqueId"] = b""
        kd["softwareEnforced"] = software
        kd["teeEnforced"] = tee

        der_bytes = encoder.encode(kd)
        log(
            f"KeyDescription DER generated: {len(der_bytes)} bytes",
            console=False,
        )
        return der_bytes
    except Exception as e:
        log_exception(e, "create_keydescription_asn1")
        return b""


def run_prettify_script(output_folder: str) -> bool:
    try:
        keybox_xml_path = os.path.join(output_folder, "keybox.xml")
        prettify_script = os.path.join(
            os.path.dirname(__file__), "prettify_xml.py"
        )

        if not os.path.exists(keybox_xml_path):
            log("keybox.xml not found, cannot prettify", level="WARN")
            return False

        if not os.path.exists(prettify_script):
            log(
                "prettify_xml.py not found, skipping prettification",
                level="WARN",
                console=False,
            )
            return False

        log(f"Running prettify_xml.py on {keybox_xml_path}", console=False)
        result = run(
            f'python3 "{prettify_script}" "{keybox_xml_path}" --overwrite',
            silent=True,
        )

        return result == 0
    except Exception as e:
        log_exception(e, "run_prettify_script")
        return False


def delete_if_empty(path: str) -> None:
    """Delete directory if it is empty (no files or subdirectories)."""
    try:
        if os.path.isdir(path) and not os.listdir(path):
            os.rmdir(path)
            log(f"Deleted empty folder: {path}", level="OK")
    except Exception as e:
        log_exception(e, f"delete_if_empty({path})")


def generate_chain(num_certs: int) -> bool:
    log(
        f"Generating AOSP {num_certs}-certificate chain with NEW CA hierarchy",
        console=False,
    )
    output_folder = create_timestamped_folder(num_certs)
    init_logging(output_folder)

    device_id = "".join([choice(CHARSET) for _ in range(randint(LB, UB))])
    log(f"Device ID: {device_id}")

    os.makedirs(os.path.join(output_folder, "newcerts"), exist_ok=True)
    write_text(os.path.join(output_folder, "index.txt"), "")
    write_text(os.path.join(output_folder, "serial"), "01")

    cnf_src = os.path.join(os.path.dirname(__file__), "openssl_aosp.cnf")
    cnf_dst = os.path.join(output_folder, "openssl_aosp.cnf")

    if not os.path.exists(cnf_src):
        log(f"openssl_aosp.cnf not found at {cnf_src}", level="ERROR")
        return False

    try:
        with open(cnf_src, "r", encoding="utf-8") as f:
            cnf_text = f.read()

        kd_der = create_keydescription_asn1()
        if kd_der:
            keydesc_hex = kd_der.hex()
            log(
                f"KeyDescription HEX injected: {len(keydesc_hex)} chars",
                console=False,
            )
            cnf_text = cnf_text.replace("KEYDESC_HEX_PLACEHOLDER", keydesc_hex)

        write_text(cnf_dst, cnf_text)
        log(
            "OpenSSL config prepared with KeyDescription",
            level="OK",
            console=False,
        )
    except Exception as e:
        log_exception(e, "config preparation")
        return False

    cnf_req = f'-config "{cnf_dst}"'
    cnf_x509 = f'-extfile "{cnf_dst}"'

    ec_root_key = os.path.join(output_folder, "ec_root.key")
    ec_root_crt = os.path.join(output_folder, "ec_root.pem")
    if run(
        f'openssl ecparam -name prime256v1 -genkey -out "{ec_root_key}"',
        silent=True,
    ) != 0:
        return False
    if run(
        f'openssl req -new -x509 -key "{ec_root_key}" -out "{ec_root_crt}" '
        f'-days 7300 -subj "{AOSP_ROOT_SUBJ}" {cnf_req} -extensions v3_root',
        silent=True,
    ) != 0:
        return False

    ec_int_key = os.path.join(output_folder, "ec_int.key")
    ec_int_csr = os.path.join(output_folder, "ec_int.csr")
    ec_int_crt = os.path.join(output_folder, "ec_int.pem")
    if run(
        f'openssl ecparam -name prime256v1 -genkey -out "{ec_int_key}"',
        silent=True,
    ) != 0:
        return False
    if run(
        f'openssl req -new -key "{ec_int_key}" -out "{ec_int_csr}" '
        f'-subj "{AOSP_INT_SUBJ}" {cnf_req}',
        silent=True,
    ) != 0:
        return False
    if run(
        f'openssl x509 -req -in "{ec_int_csr}" -CA "{ec_root_crt}" '
        f'-CAkey "{ec_root_key}" -CAcreateserial -out "{ec_int_crt}" '
        f'-days 3650 {cnf_x509} -extensions v3_intermediate',
        silent=True,
    ) != 0:
        return False

    ec_leaf_key = os.path.join(output_folder, "ecPrivateKey.pem")
    ec_leaf_csr = os.path.join(output_folder, "ec_leaf.csr")
    ec_leaf_crt = os.path.join(output_folder, "ecCert_1.pem")
    if run(
        f'openssl ecparam -name prime256v1 -genkey -out "{ec_leaf_key}"',
        silent=True,
    ) != 0:
        return False
    if run(
        f'openssl req -new -key "{ec_leaf_key}" -out "{ec_leaf_csr}" '
        f'-subj "{AOSP_LEAF_SUBJ_EC}" {cnf_req}',
        silent=True,
    ) != 0:
        return False
    if run(
        f'openssl x509 -req -in "{ec_leaf_csr}" -CA "{ec_int_crt}" '
        f'-CAkey "{ec_int_key}" -CAcreateserial -out "{ec_leaf_crt}" '
        f'-days 3650 {cnf_x509} -extensions v3_leaf_ec',
        silent=True,
    ) != 0:
        return False

    ec_cert2 = os.path.join(output_folder, "ecCert_2.pem")
    ec_cert3 = os.path.join(output_folder, "ecCert_3.pem")
    run(f'cp "{ec_int_crt}" "{ec_cert2}"', silent=True)
    run(f'cp "{ec_root_crt}" "{ec_cert3}"', silent=True)

    rsa_root_key = os.path.join(output_folder, "rsa_root.key")
    rsa_root_crt = os.path.join(output_folder, "rsa_root.pem")
    if run(f'openssl genrsa -out "{rsa_root_key}" 2048', silent=True) != 0:
        return False
    if run(
        f'openssl req -new -x509 -key "{rsa_root_key}" -out "{rsa_root_crt}" '
        f'-days 7300 -subj "{AOSP_ROOT_SUBJ}" {cnf_req} -extensions v3_root',
        silent=True,
    ) != 0:
        return False

    rsa_int_key = os.path.join(output_folder, "rsa_int.key")
    rsa_int_csr = os.path.join(output_folder, "rsa_int.csr")
    rsa_int_crt = os.path.join(output_folder, "rsa_int.pem")
    if run(f'openssl genrsa -out "{rsa_int_key}" 2048', silent=True) != 0:
        return False
    if run(
        f'openssl req -new -key "{rsa_int_key}" -out "{rsa_int_csr}" '
        f'-subj "{AOSP_INT_SUBJ}" {cnf_req}',
        silent=True,
    ) != 0:
        return False
    if run(
        f'openssl x509 -req -in "{rsa_int_csr}" -CA "{rsa_root_crt}" '
        f'-CAkey "{rsa_root_key}" -CAcreateserial -out "{rsa_int_crt}" '
        f'-days 3650 {cnf_x509} -extensions v3_intermediate',
        silent=True,
    ) != 0:
        return False

    rsa_leaf_key = os.path.join(output_folder, "rsaPrivateKey.pem")
    rsa_leaf_csr = os.path.join(output_folder, "rsa_leaf.csr")
    rsa_leaf_crt = os.path.join(output_folder, "rsaCert_1.pem")
    if run(f'openssl genrsa -out "{rsa_leaf_key}" 2048', silent=True) != 0:
        return False
    if run(
        f'openssl req -new -key "{rsa_leaf_key}" -out "{rsa_leaf_csr}" '
        f'-subj "{AOSP_LEAF_SUBJ_RSA}" {cnf_req}',
        silent=True,
    ) != 0:
        return False
    if run(
        f'openssl x509 -req -in "{rsa_leaf_csr}" -CA "{rsa_int_crt}" '
        f'-CAkey "{rsa_int_key}" -CAcreateserial -out "{rsa_leaf_crt}" '
        f'-days 3650 {cnf_x509} -extensions v3_leaf_rsa',
        silent=True,
    ) != 0:
        return False

    rsa_cert2 = os.path.join(output_folder, "rsaCert_2.pem")
    rsa_cert3 = os.path.join(output_folder, "rsaCert_3.pem")
    run(f'cp "{rsa_int_crt}" "{rsa_cert2}"', silent=True)
    run(f'cp "{rsa_root_crt}" "{rsa_cert3}"', silent=True)

    try:
        ec_priv_pem = read_text(ec_leaf_key)
        rsa_priv_pem = read_text(rsa_leaf_key)

        ec_chain_pems = [
            read_text(ec_leaf_crt),
            read_text(ec_cert2),
            read_text(ec_cert3),
        ]
        rsa_chain_pems = [
            read_text(rsa_leaf_crt),
            read_text(rsa_cert2),
            read_text(rsa_cert3),
        ]

        ec_chain_xml = format_chain_xml(ec_chain_pems)
        rsa_chain_xml = format_chain_xml(rsa_chain_pems)

        keybox_xml = keyboxFormatter.format(
            device_id=device_id,
            ec_priv=ec_priv_pem,
            count=num_certs,
            ec_chain=ec_chain_xml,
            rsa_priv=rsa_priv_pem,
            rsa_chain=rsa_chain_xml,
        )

        keybox_path = os.path.join(output_folder, "keybox.xml")
        if not validate_xml(keybox_xml):
            log("XML validation warning (continuing)", level="WARN")

        write_text(keybox_path, keybox_xml)
        log(
            f"Keybox XML generated: {keybox_path} ({len(keybox_xml)} bytes)",
            level="OK",
        )

        run_prettify_script(output_folder)

        cleanup_intermediate_files(output_folder)

        # Delete folder if it ended up empty after cleanup.
        delete_if_empty(output_folder)

        log(
            f"Successfully generated {num_certs}-cert chain with CA "
            f"hierarchy + KeyDescription",
            level="OK",
        )
        print(f"[OK] Chain {num_certs} complete: {output_folder}")
        return True

    except Exception as e:
        log_exception(e, "keybox assembly")
        return False


def pressTheEnterKeyToExit(errorLevel=None) -> None:
    try:
        if errorLevel == EXIT_SUCCESS:
            log("Generation completed successfully", level="OK", console=False)
        elif isinstance(errorLevel, int):
            log(
                f"Generation failed with exit code: {errorLevel}",
                level="ERROR",
                console=False,
            )
        close_logging()

        is_ci = (
            os.environ.get("CI")
            or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("GITLAB_CI")
            or os.environ.get("CIRCLECI")
            or os.environ.get("TRAVIS")
            or os.environ.get("JENKINS_URL")
        )

        if not is_ci:
            try:
                input("Press Enter to exit...")
            except (EOFError, KeyboardInterrupt):
                pass
    except Exception:
        pass


def main() -> int:
    try:
        print("AOSP Keybox Generator")
        print("Generating attestation keyboxes...")

        log("AOSP Keybox Generator", console=False)
        log(f"Python version: {sys.version}", console=False)
        log(f"Working directory: {os.getcwd()}", console=False)

        if subprocess.call(
            "openssl version",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) != 0:
            print("[ERROR] OpenSSL not found in PATH")
            return EXIT_FAILURE

        if not LXML_AVAILABLE:
            log(
                "lxml not installed - install with: python3 -m pip install lxml",
                level="WARN",
            )
        if not ASN1_AVAILABLE:
            log(
                "pyasn1 not installed - install with: python3 -m pip install pyasn1",
                level="WARN",
            )
        else:
            kd_test = create_keydescription_asn1()
            if kd_test:
                log(
                    f"KeyDescription test: {len(kd_test)} bytes OK",
                    console=False,
                )

        print("[INFO] Requires openssl_aosp.cnf in script directory")

        for chain_length in [1, 2, 3]:
            log(
                f"Starting NEW generation for {chain_length}-certificate chain",
                console=False,
            )
            if not generate_chain(chain_length):
                log(
                    f"Failed to generate {chain_length}-certificate chain",
                    level="ERROR",
                )
                pressTheEnterKeyToExit(EXIT_FAILURE)
                return EXIT_FAILURE

        log(
            "All NEW certificate chains generated successfully",
            level="OK",
        )

        print("\nOutput locations:")
        for folder in sorted(
            [
                f
                for f in os.listdir(".")
                if f.endswith("-aosp-chain1")
                or f.endswith("-aosp-chain2")
                or f.endswith("-aosp-chain3")
            ]
        ):
            if os.path.isdir(folder):
                print(f"  • {folder}")

        pressTheEnterKeyToExit(EXIT_SUCCESS)
        return EXIT_SUCCESS

    except KeyboardInterrupt:
        log("Generation interrupted by user", level="WARN")
        print("\n[INTERRUPTED] User cancelled")
        close_logging()
        return EXIT_FAILURE
    except Exception as e:
        log_exception(e, "main")
        print(f"\n[FATAL] {str(e)}")
        print("Check generation.log for details")
        close_logging()
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
