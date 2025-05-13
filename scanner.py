import os
import gzip
import requests
import hashlib
import ecdsa
import base58
import time
from datetime import datetime
from multiprocessing import Pool, Manager, cpu_count
from io import BytesIO

# Configuration
TSV_GZ_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
WORKERS = cpu_count()  # Use all available cores
BATCH_SIZE = 250000  # Keys per worker per batch
UPDATE_INTERVAL = 2  # Seconds between stats updates

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_targets():
    """Load addresses with balances from TSV.GZ"""
    print(f"{timestamp()} | Loading address database...")
    response = requests.get(TSV_GZ_URL, stream=True)
    response.raise_for_status()
    
    targets = {}
    with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
        for line in f:
            try:
                addr, balance = line.decode().strip().split('\t')[:2]
                targets[addr] = int(float(balance))
            except:
                continue
    
    print(f"{timestamp()} | Loaded {len(targets):,} addresses")
    return targets

def generate_batch(batch_size):
    """Generate crypto-secure private keys"""
    return [os.urandom(32) for _ in range(batch_size)]

def process_key(pk):
    """Process single private key"""
    # Address generation
    sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
    x = sk.verifying_key.pubkey.point.x()
    y = sk.verifying_key.pubkey.point.y()
    compressed_pub = (b'\x03' if y % 2 else b'\x02') + x.to_bytes(32, 'big')
    h160 = hashlib.new('ripemd160', hashlib.sha256(compressed_pub).digest()).digest()
    addr = base58.b58encode_check(b'\x00' + h160).decode()
    
    # WIF generation
    wif = base58.b58encode_check(b'\x80' + pk + b'\x01').decode()
    
    return addr, wif

def worker(targets, result_queue, stats):
    """Worker process with optimized batch processing"""
    while True:
        batch = generate_batch(BATCH_SIZE // WORKERS)
        start_time = time.time()
        
        # Process batch in parallel chunks
        with Pool(WORKERS) as p:
            results = p.map(process_key, batch)
        
        # Check matches
        found = []
        for addr, wif in results:
            if addr in targets:
                found.append(f"{timestamp()}|{addr}|{wif}|{targets[addr]}\n")
        
        # Update stats
        with stats.get_lock():
            stats['total'] += len(batch)
            stats['speed'] = len(batch) / (time.time() - start_time)
        
        # Send results to main process
        if found:
            result_queue.put(found)

def main():
    print(f"\n{timestamp()} | Starting BTC Scanner | Cores: {WORKERS}")
    targets = load_targets()
    
    manager = Manager()
    result_queue = manager.Queue()
    stats = manager.dict({'total': 0, 'speed': 0})
    
    # Start worker processes
    pool = Pool(WORKERS, worker, (targets, result_queue, stats))
    
    try:
        last_update = time.time()
        while True:
            # Save results if available
            if not result_queue.empty():
                with open("found.txt", "a") as f:
                    while not result_queue.empty():
                        f.writelines(result_queue.get())
            
            # Print stats periodically
            if time.time() - last_update > UPDATE_INTERVAL:
                print(
                    f"\r{timestamp()} | "
                    f"Checked {stats['total']:,} | "
                    f"Speed: {stats['speed']/1000:,.1f}K keys/sec | "
                    f"Workers: {WORKERS}", 
                    end="", flush=True
                )
                last_update = time.time()
            
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print("\nShutting down workers...")
        pool.terminate()
        pool.join()
        
        # Final save
        with open("found.txt", "a") as f:
            while not result_queue.empty():
                f.writelines(result_queue.get())
        
        print(f"\n{timestamp()} | Final count: {stats['total']:,} keys checked")

if __name__ == "__main__":
    main()
