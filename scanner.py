#!/usr/bin/env python3
import os
import sys
import gzip
import requests
import hashlib
import ecdsa
import base58
import time
import psutil
from datetime import datetime
from multiprocessing import Pool, Manager, cpu_count
from io import BytesIO

# ================ CONFIGURATION ================
TSV_GZ_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
UPDATE_INTERVAL = 5  # Seconds between stats updates
SAFE_RAM_USAGE = 0.7  # 70% of available RAM for safety
MIN_BATCH_SIZE = 50000
MAX_BATCH_SIZE = 200000

# ================ SYSTEM OPTIMIZATION ================
def optimize_system():
    """Increase system limits for better performance"""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
    except:
        pass

    # Set process priority
    try:
        if os.name == 'posix':
            os.nice(-10)  # Higher priority on Linux/macOS
    except:
        pass

# ================ MEMORY MANAGEMENT ================
def get_safe_batch_size():
    """Calculate batch size based on available RAM"""
    available_ram = psutil.virtual_memory().available
    bytes_per_key = 34  # Estimated memory per key
    safe_ram = available_ram * SAFE_RAM_USAGE
    
    batch_size = int(safe_ram / bytes_per_key)
    return max(MIN_BATCH_SIZE, min(batch_size, MAX_BATCH_SIZE))

# ================ CORE FUNCTIONS ================
def load_targets():
    """Load address database with memory safety"""
    print("\n[•] Loading address database (this may take a minute)...")
    mem_before = psutil.virtual_memory().used
    
    try:
        response = requests.get(TSV_GZ_URL, stream=True, timeout=60)
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
                
                # Memory protection
                if len(targets) % 1000000 == 0:
                    current_mem = psutil.virtual_memory()
                    if current_mem.percent > 90:
                        print("\n[!] Approaching memory limit, stopping load early")
                        break
        
        mem_used = (psutil.virtual_memory().used - mem_before) / (1024**2)
        print(f"[✓] Loaded {len(targets):,} addresses | RAM Used: {mem_used:.1f}MB")
        return targets
    
    except Exception as e:
        print(f"\n[×] Failed to load database: {str(e)}")
        raise

def worker_process(batch, targets):
    """Optimized worker with efficient memory usage"""
    results = []
    for pk in batch:
        # Address generation
        sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
        x = sk.verifying_key.pubkey.point.x()
        y = sk.verifying_key.pubkey.point.y()
        pubkey = (b'\x03' if y % 2 else b'\x02') + x.to_bytes(32, 'big')
        h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
        addr = base58.b58encode_check(b'\x00' + h160).decode()
        
        if addr in targets:
            wif = base58.b58encode_check(b'\x80' + pk + b'\x01').decode()
            results.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|{addr}|{wif}\n")
    
    return results

# ================ MAIN CONTROLLER ================
def main():
    optimize_system()
    
    # Load targets first
    targets = load_targets()
    if not targets:
        print("[×] No targets loaded - exiting")
        return
    
    workers = min(cpu_count(), 4)  # Limit to 4 workers for stability
    batch_size = get_safe_batch_size()
    
    print(f"\n[•] Starting scan with {workers} workers | Batch size: {batch_size:,}")
    print("==========================================")
    
    with Manager() as manager:
        result_queue = manager.Queue()
        stats = manager.dict({
            'total': 0,
            'speed': 0,
            'start_time': time.time(),
            'found': 0
        })
        
        with Pool(workers) as pool:
            try:
                while True:
                    # Generate and process batch
                    batch = [os.urandom(32) for _ in range(batch_size)]
                    pool.apply_async(
                        worker_process,
                        args=(batch, targets),
                        callback=lambda r: (result_queue.put(r), stats.update({'found': stats['found'] + len(r)})) if r else None
                    )
                    
                    # Update stats
                    stats['total'] += len(batch)
                    stats['speed'] = len(batch) / (time.time() - stats.get('last_batch_time', time.time()))
                    stats['last_batch_time'] = time.time()
                    
                    # Display stats
                    ram = psutil.virtual_memory()
                    print(
                        f"\r[•] Keys: {stats['total']:,} | "
                        f"Speed: {stats['speed']/1000:,.1f}K/s | "
                        f"Found: {stats['found']} | "
                        f"RAM: {ram.percent}%",
                        end="", flush=True
                    )
                    
                    # Adjust batch size dynamically
                    new_batch_size = get_safe_batch_size()
                    if new_batch_size != batch_size:
                        batch_size = new_batch_size
                        print(f"\n[•] Adjusted batch size to {batch_size:,} based on RAM availability")
                    
                    # Save results periodically
                    if not result_queue.empty():
                        with open("found.txt", "a") as f:
                            while not result_queue.empty():
                                f.writelines(result_queue.get())
                    
                    time.sleep(0.1)
                    
            except KeyboardInterrupt:
                print("\n[!] Shutting down workers...")
                pool.close()
                pool.join()
                
                # Final save
                with open("found.txt", "a") as f:
                    while not result_queue.empty():
                        f.writelines(result_queue.get())
                
                # Final report
                total_time = time.time() - stats['start_time']
                print("\n==========================================")
                print(f" Total Runtime: {total_time/3600:.2f} hours")
                print(f" Keys Checked: {stats['total']:,}")
                print(f" Average Speed: {stats['total']/total_time:,.0f} keys/sec")
                print(f" Addresses Found: {stats['found']}")
                print("==========================================")

if __name__ == "__main__":
    # Ensure clean restart
    if '--clean' not in sys.argv:
        os.execv(sys.executable, [sys.executable] + sys.argv + ['--clean'])
    main()
