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
WORKERS = min(4, cpu_count())  # Use 4 cores or available cores
BATCH_SIZE = 50000  # Keys per batch per worker
UPDATE_INTERVAL = 1  # Seconds between stats updates

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_targets():
    """Load addresses with minimal memory usage"""
    print(f"{timestamp()} | Loading address database...")
    response = requests.get(TSV_GZ_URL, stream=True)
    response.raise_for_status()
    
    targets = set()
    with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
        for line in f:
            try:
                addr = line.decode().split('\t')[0]
                if 26 <= len(addr) <= 35:  # Basic validation
                    targets.add(addr)
            except:
                continue
    
    print(f"{timestamp()} | Loaded {len(targets):,} addresses")
    return targets

def worker_init(targets):
    """Initialize worker with read-only target addresses"""
    global worker_targets
    worker_targets = targets

def process_batch(batch):
    """Process a batch of keys"""
    results = []
    for pk in batch:
        # Generate address
        sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
        x = sk.verifying_key.pubkey.point.x()
        y = sk.verifying_key.pubkey.point.y()
        pubkey = (b'\x03' if y % 2 else b'\x02') + x.to_bytes(32, 'big')
        h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
        addr = base58.b58encode_check(b'\x00' + h160).decode()
        
        # Check match
        if addr in worker_targets:
            wif = base58.b58encode_check(b'\x80' + pk + b'\x01').decode()
            results.append(f"{timestamp()}|{addr}|{wif}\n")
    
    return results

def main():
    print(f"\n{timestamp()} | Starting BTC Scanner | Cores: {WORKERS}")
    targets = load_targets()
    
    manager = Manager()
    result_queue = manager.Queue()
    stats = manager.dict({'total': 0, 'speed': 0})
    
    # Initialize worker pool
    with Pool(
        processes=WORKERS,
        initializer=worker_init,
        initargs=(targets,)
    ) as pool:
        try:
            last_update = time.time()
            batch_count = 0
            
            while True:
                # Generate new batch
                batch = [os.urandom(32) for _ in range(BATCH_SIZE)]
                batch_count += 1
                
                # Process batch asynchronously
                pool.apply_async(
                    process_batch,
                    args=(batch,),
                    callback=lambda r: result_queue.put(r) if r else None
                )
                
                # Update stats
                with stats.get_lock():
                    stats['total'] += len(batch)
                    stats['speed'] = len(batch) / (time.time() - last_update)
                    last_update = time.time()
                
                # Save results periodically
                if batch_count % 10 == 0:  # Every 10 batches
                    if not result_queue.empty():
                        with open("found.txt", "a") as f:
                            while not result_queue.empty():
                                f.writelines(result_queue.get())
                
                # Print stats
                print(
                    f"\r{timestamp()} | "
                    f"Keys: {stats['total']:,} | "
                    f"Speed: {stats['speed']/1000:,.1f}K/s | "
                    f"Workers: {WORKERS}", 
                    end="", flush=True
                )
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\nShutting down workers...")
            pool.close()
            pool.join()
            
            # Final save
            with open("found.txt", "a") as f:
                while not result_queue.empty():
                    f.writelines(result_queue.get())
            
            print(f"\n{timestamp()} | Final count: {stats['total']:,} keys")

if __name__ == "__main__":
    # Set higher file descriptor limit
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
    
    main()
