import os
import gzip
import requests
import hashlib
import ecdsa
import base58
import time
from datetime import datetime

# Configuration
TSV_GZ_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
BATCH_SIZE = 100000  # Keys per iteration
SAVE_INTERVAL = 300  # Seconds between saves

def load_targets():
    """Load addresses with balances from TSV.GZ"""
    print(f"{timestamp()} | Loading address database...")
    response = requests.get(TSV_GZ_URL, stream=True)
    response.raise_for_status()
    
    targets = {}
    with gzip.GzipFile(fileobj=response.raw) as f:
        for line in f:
            try:
                addr, balance = line.decode().strip().split('\t')[:2]
                targets[addr] = int(float(balance))
            except:
                continue
    
    print(f"{timestamp()} | Loaded {len(targets):,} addresses")
    return targets

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def scan(targets):
    checked = 0
    last_save = time.time()
    
    while True:
        # Generate batch
        batch = [os.urandom(32) for _ in range(BATCH_SIZE)]
        
        # Process batch
        for pk in batch:
            # Address generation
            sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
            x = sk.verifying_key.pubkey.point.x()
            y = sk.verifying_key.pubkey.point.y()
            compressed_pub = (b'\x03' if y % 2 else b'\x02') + x.to_bytes(32, 'big')
            h160 = hashlib.new('ripemd160', hashlib.sha256(compressed_pub).digest()).digest()
            addr = base58.b58encode_check(b'\x00' + h160).decode()
            
            # WIF generation
            wif = base58.b58encode_check(b'\x80' + pk + b'\x01').decode()
            
            # Check match
            if addr in targets:
                with open("found.txt", "a") as f:
                    f.write(f"{timestamp()}|{addr}|{wif}|{targets[addr]}\n")
                print(f"\nFOUND: {addr} | Balance: {targets[addr]:,} satoshis")
            
            checked += 1
            if checked % 10000 == 0:
                print(f"\r{timestamp()} | Checked {checked:,} keys | Last: {addr}", end="")
        
        # Periodic save
        if time.time() - last_save > SAVE_INTERVAL:
            print(f"\n{timestamp()} | Progress saved | Total: {checked:,} keys")
            last_save = time.time()

if __name__ == "__main__":
    targets = load_targets()
    scan(targets)
