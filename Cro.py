import hashlib
import binascii
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import time
import random

# التأكد من تثبيت coincurve
try:
    import coincurve
except ImportError:
    raise ImportError("Please install coincurve using: pip install coincurve")

def base58_encode(b: bytes) -> str:
    """ترميز Base58 (Bitcoin Base58Check encoding)."""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, 'big')
    encode = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encode = alphabet[rem] + encode
    n_pad = sum(1 for byte in b if byte == 0)
    return '1' * n_pad + encode

def private_key_to_address(private_key_hex: str) -> str:
    """تحويل المفتاح الخاص إلى عنوان بيتكوين."""
    try:
        priv_key_bytes = binascii.unhexlify(private_key_hex.zfill(64))
        privkey_obj = coincurve.PrivateKey(priv_key_bytes)
        pubkey = privkey_obj.public_key.format(compressed=True)
        sha256_pub = hashlib.sha256(pubkey).digest()
        ripemd160 = hashlib.new('ripemd160', sha256_pub).digest()
        address_bytes = b'\x00' + ripemd160
        checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
        return base58_encode(address_bytes + checksum)
    except Exception:
        return ""

def parallel_search(args):
    """البحث الموازي مع التتبع لكل مليون عملية."""
    start_key, end_key, target_address, batch_size = args
    current = start_key
    found = None
    checked = 0
    start_time = time.time()

    while current <= end_key:
        batch_end = min(current + batch_size, end_key + 1)
        batch_keys = [hex(k)[2:].zfill(64) for k in range(current, batch_end)]
        
        for key in batch_keys:
            checked += 1
            if private_key_to_address(key) == target_address:
                return key
            
            # تتبع كل مليون عملية
            if checked % 1_000_000 == 0:
                elapsed = time.time() - start_time
                print(f"Checked: {checked} keys, Time: {elapsed:.2f} sec")
        
        current = batch_end
    return None

def find_key_combined(start_key_hex, end_key_hex, target_address, batch_size):
    """البحث عن المفتاح باستخدام أقصى عدد من الأنوية."""
    num_processes = multiprocessing.cpu_count()  # استخدام أقصى عدد من الأنوية
    start_key = int(start_key_hex, 16)
    end_key = int(end_key_hex, 16)
    total_keys = end_key - start_key + 1
    step = total_keys // num_processes

    parallel_args = [
        (start_key + i * step, end_key if i == num_processes - 1 else start_key + (i + 1) * step - 1, target_address, batch_size)
        for i in range(num_processes)
    ]

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(parallel_search, arg) for arg in parallel_args]

        for future in as_completed(futures):
            result = future.result()
            if result:
                # عند العثور على المفتاح، يتم إلغاء باقي العمليات
                for f in futures:
                    f.cancel()
                return result
    return None

if __name__ == '__main__':
    # إضافة المدخلات المحددة دون استخدام إدخال من المستخدم
    target_address = "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9h"
    start_key_hex = "00000000000000000000000000000000000000000000000453444835ec580037"
    end_key_hex   = "000000000000000000000000000000000000000000000007fffffffffffffff8"
    batch_size = 10000000

    start_time = time.time()
    found_key = find_key_combined(start_key_hex, end_key_hex, target_address, batch_size)
    end_time = time.time()

    if found_key:
        print(f"\nFound matching private key: {found_key}")
        with open("found_keys.txt", "a") as f:
            f.write(f"Address: {target_address} - Private Key: {found_key}\n")
    else:
        print("\nNo matching key found.")
    print(f"Search completed in {end_time - start_time:.2f} seconds.")
