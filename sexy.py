import base64
import re
import sys
import argparse
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA1, SHA256

SALT = bytes([191, 235, 30, 86, 251, 205, 151, 59, 178, 25,
              2, 36, 48, 165, 120, 67, 0, 61, 86, 68,
              210, 30, 98, 185, 212, 241, 128, 231, 230, 195,
              57, 65])

def derive_keys(master_key):
    km = PBKDF2(master_key, SALT, dkLen=96, count=50000, hmac_hash_module=SHA1)
    return km[:32], km[32:96]

def decrypt_field(encrypted_b64, aes_key, hmac_key):
    data = base64.b64decode(encrypted_b64)
    if len(data) < 48:
        raise ValueError("short data")
    iv = data[32:48]
    ct = data[48:]
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(data[32:])
    if data[:32] != h.digest():
        pass
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad = pt[-1]
    if pad < 1 or pad > 16:
        raise ValueError("bad padding")
    return pt[:-pad].decode('utf-8', errors='replace')

def extract_master_key(source):
    match = re.search(r'public\s+static\s+string\s+Key\s*=\s*"([^"]+)"', source)
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1)).decode('utf-8')
    except Exception:
        return None

def extract_fields(source):
    fields = {}
    pattern = r'public\s+static\s+string\s+(\w+)\s*=\s*"([A-Za-z0-9+/=]{20,})"'
    for match in re.finditer(pattern, source):
        name = match.group(1)
        value = match.group(2)
        if name == "Key":
            continue
        try:
            base64.b64decode(value)
            fields[name] = value
        except Exception:
            continue
    return fields

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', default=None)
    parser.add_argument('--source', '-s', default='zalupa/Client.decompiled.cs')
    args = parser.parse_args()

    source_path = Path(args.source)
    if args.input and Path(args.input).exists():
        input_path = Path(args.input)
        if input_path.suffix == '.cs':
            source_path = input_path

    if not source_path.exists():
        print(f"file not found: {source_path}")
        sys.exit(1)

    print("=" * 60)
    print("asyncrat config decryptor")
    print("=" * 60)
    print(f"source: {source_path}")
    print()

    source = source_path.read_text(encoding='utf-8', errors='replace')
    master_key = extract_master_key(source)

    if not master_key:
        print("master key not found")
        sys.exit(1)

    print(f"master key: {master_key}")
    print()

    aes_key, hmac_key = derive_keys(master_key)
    print(f"aes key:  {aes_key.hex()}")
    print(f"hmac key: {hmac_key.hex()[:32]}...")
    print()

    fields = extract_fields(source)

    if not fields:
        print("no encrypted fields found")
        sys.exit(1)

    print(f"found {len(fields)} fields")
    print()

    print("-" * 60)
    print("decrypted values")
    print("-" * 60)

    results = {}
    for name, encrypted in fields.items():
        try:
            value = decrypt_field(encrypted, aes_key, hmac_key)
            results[name] = value
            print(f"{name:15} = {value}")
        except Exception as e:
            print(f"{name:15} = error: {e}")

    print("-" * 60)
    print()

    if results:
        print("config summary:")
        print()

        known = {
            'Hosts': 'c2 server',
            'Ports': 'ports',
            'Version': 'version',
            'Install': 'install',
            'MTX': 'mutex',
            'Pastebin': 'pastebin',
            'Anti': 'anti-vm',
            'BDOS': 'critical process',
            'Certificate': 'certificate',
            'Serversignature': 'server signature',
        }

        for name, value in results.items():
            desc = known.get(name, '')
            if desc:
                print(f"  {name:15} ({desc}): {value}")
            else:
                print(f"  {name:15}: {value}")

        print()

        output_file = source_path.parent / "decrypted_config.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            for name, value in results.items():
                f.write(f"{name}={value}\n")

        print(f"saved to: {output_file}")

if __name__ == '__main__':
    main()
