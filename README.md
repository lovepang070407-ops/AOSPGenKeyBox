# AOSPGenKeyBox

**AOSP-like Keybox Generator** - Generates Android Keystore attestation keyboxes with proper CA hierarchy and ASN.1 KeyDescription extension.  
(OID 1.3.6.1.4.1.11129.2.1.17)

## Features

- Generates 1-, 2-, and 3-certificate chains  
- Full CA hierarchy: Root → Intermediate → Leaf  
- ECDSA (P-256) and RSA (2048) keypairs  
- KeyDescription ASN.1 structure injection  
- Timestamped UTC folders with minimal essential files only  
- Comprehensive logging (`generation.log` per chain)  

## Output Files (per chain)

```
202*-*-UTC-aosp-chainX/
├── keybox.xml                 # Main attestation keybox
├── ecPrivateKey.pem           # EC leaf private key
├── rsaPrivateKey.pem          # RSA leaf private key  
├── ecCert_1.pem               # EC leaf certificate
├── ecCert_2.pem               # EC intermediate
├── ecCert_3.pem               # EC root
├── rsaCert_1.pem              # RSA leaf certificate
├── rsaCert_2.pem              # RSA intermediate
├── rsaCert_3.pem              # RSA root
├── generation.log             # Detailed logs
└── openssl_aosp.cnf           # Generated config
```

## Prerequisites

Install dependencies via:

```
pip install -r requirements.txt
```

*Required software:*

- `openssl` (version 1.1.1+ required)

*Optional Python packages:*

- `lxml` and `pyasn1` (for XML validation and KeyDescription ASN.1 encoding)

## Required Files

- `openssl_aosp.cnf` - OpenSSL config file, placed in the same directory as the script.  
- `prettify_xml.py` - XML formatting helper script.

## Usage

Run interactively (prompts for Enter key to exit):

```
python3 aosp_keybox_generator.py
```

For CI/CD pipelines, disable prompt with:

```
CI=true python3 aosp_keybox_generator.py
```

## Expected Console Output

```
AOSP Keybox Generator v2.1
Generating attestation keyboxes...
[INFO] Requires openssl_aosp.cnf in script directory
[OK] Chain 1 complete: 202*-*-UTC-aosp-chainX
[OK] Chain 2 complete: 202*-*-UTC-aosp-chainX  
[OK] Chain 3 complete: 202*-*-UTC-aosp-chainX

Output locations:
  • 202*-*-UTC-aosp-chainX
  • 202*-*-UTC-aosp-chainX
  • 202*-*-UTC-aosp-chainX
```

## Keybox Structure

Generated `keybox.xml` follows Android Open Source Project (AOSP) format:

```xml
<?xml version="1.0"?>
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="rVwy78oa55xj">
    <Key algorithm="ecdsa">...</Key>
    <Key algorithm="rsa">...</Key>
  </Keybox>
</AndroidAttestation>
```

## ⚠️ Important Notes

- **TEST ONLY** - Template code; not production or real device keyboxes.  
- Fails Google Play Integrity validation (not signed by Google).  
- Intended for Android Keystore attestation development/testing.  
- DeviceID is random per run (6-12 characters).  

## Troubleshooting

| Issue                      | Solution                                   |
|----------------------------|--------------------------------------------|
| `OpenSSL not found`        | Install OpenSSL or add it to your PATH.   |
| `openssl_aosp.cnf missing` | Place `openssl_aosp.cnf` in script directory. |
| XML validation warnings    | Install `lxml`: `pip install lxml`         |
| Missing KeyDescription     | Install `pyasn1`: `pip install pyasn1`     |

## Automation / CI Integration Example

```
- name: Generate AOSP keyboxes
  run: |
    CI=true python3 aosp_keybox_generator.py
    ls -la *-aosp-chain*
  shell: bash
```

## License

This project is licensed under the **GPLv3** License. See [LICENSE](./LICENSE) for details.
