import os
import gzip
import requests
import hashlib
import ecdsa
import base58
import time
from datetime import datetime
from multiprocessing import Pool, Manager, cpu_count, current_process
from io import BytesIO
import psutil  # For RAM monitoring
import resource

# Configuration
TSV_GZ_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
UPDATE_INTERVAL = 5  # Seconds between stats updates

# Dynamic scaling based on available resources
TOTAL_CORES = cpu_count()
MAX_RAM_GB = psutil.virtual_memory().total / (1024 ** 3)
BATCH_SIZE = max(100000, int(50000 * MAX_RAM_GB))  # Scale with RAM
WORKERS = TOTAL_CORES  # Use all cores

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def optimize_system():
    """Increase system limits for maximum performance"""
    # Increase file descriptor limit
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
    # Set high priority
    os.nice(-15)

def load_targets():
    """Load addresses using maximum available RAM efficiently"""
    print(f"{timestamp()} | Loading database (Using {MAX_RAM_GB:.1f}GB RAM)...")
    
    # Allocate up to 80% of available RAM for targets
    max_target_mem = MAX_RAM_GB * 0.8 * (1024 ** 3)
    targets = set()
    entry_size = 60  # Approx bytes per address
    
    response = requests.get(TSV_GZ_URL, stream=True)
    response.raise_for_status()
    
    with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
        for line in f:
            try:
                addr = line.decode().split('\t')[0]
                if 26 <= len(addr) <= 35:  # Basic validation
                    targets.add(addr)
                    
                    # Stop if approaching memory limit
                    if len(targets) * entry_size > max_target_mem * 0.9:
                        print(f"{timestamp()} | Memory limit reached, loaded {len(targets):,} addresses")
                        break
            except:
                continue
    
    print(f"{timestamp()} | Loaded {len(targets):,} addresses into RAM")
    return targets

def worker_process(batch, targets):
    """Optimized worker using C-optimized crypto"""
    results = []
    for pk in batch:
        # Ultra-fast address generation
        sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
        x = sk.verifying_key.pubkey.point.x()
        y = sk.verifying_key.pubkey.point.y()
        pubkey = (b'\x03' if y % 2 else b'\x02') + x.to_bytes(32, 'big')
        h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
        addr = base58.b58encode_check(b'\x00' + h160).decode()
        
        if addr in targets:
            wif = base58.b58encode_check(b'\x80' + pk + b'\x01').decode()
            results.append(f"{timestamp()}|{addr}|{wif}\n")
    
    return results

def batch_generator():
    """Infinite batch generator with optimized memory cycling"""
    while True:
        yield [os.urandom(32) for _ in range(BATCH_SIZE)]

def main():
    optimize_system()
    print(f"\n{timestamp()} | Starting Ultra Scanner | Cores: {WORKERS} | RAM: {MAX_RAM_GB:.1f}GB")
    
    targets = load_targets()
    gen = batch_generator()
    
    with Manager() as manager:
        result_queue = manager.Queue()
        stats = manager.dict({
            'total': 0,
            'speed': 0,
            'last_batch_time': time.time()
        })
        
        with Pool(WORKERS) as pool:
            try:
                print(f"{timestamp()} | Workers ready | Batch size: {BATCH_SIZE:,}")
                print("=" * 80)
                print(" Time       | Keys Checked  | Speed (keys/sec) | RAM Usage ")
                print("=" * 80)
                
                while True:
                    # Submit new batch
                    batch = next(gen)
                    pool.apply_async(
                        worker_process,
                        args=(batch, targets),
                        callback=lambda r: result_queue.put(r) if r else None
                    )
                    
                    # Update stats
                    stats['total'] += len(batch)
                    now = time.time()
                    stats['speed'] = len(batch) / (now - stats['last_batch_time'])
                    stats['last_batch_time'] = now
                    
                    # Display real-time stats
                    ram_percent = psutil.virtual_memory().percent
                    print(
                        f"\r{timestamp()} | "
                        f"{stats['total']:,} | "
                        f"{stats['speed']:,.0f} | "
                        f"{ram_percent}%",
                        end="", flush=True
                    )
                    
                    # Save results without blocking
                    if not result_queue.empty():
                        with open("found.txt", "a") as f:
                            while not result_queue.empty():
                                f.writelines(result_queue.get())
                    
                    time.sleep(0.1)
                    
            except KeyboardInterrupt:
                print("\n\nShutting down workers gracefully...")
                pool.close()
                pool.join()
                
                # Final save
                with open("found.txt", "a") as f:
                    while not result_queue.empty():
                        f.writelines(result_queue.get())
                
                total_time = time.time() - stats['start_time']
                print(f"\n{timestamp()} | Scan completed")
                print(f"Total keys checked: {stats['total']:,}")
                print(f"Average speed: {stats['total']/total_time:,.0f} keys/sec")

if __name__ == "__main__":
    # Set process priority
    try:
        import sys
        if sys.platform == 'linux':
            os.system("sudo renice -n -15 -p $$ 2>/dev/null")
    except:
        pass
    
    main()
