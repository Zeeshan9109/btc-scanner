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
import signal
from datetime import datetime
from multiprocessing import Pool, Manager, cpu_count
from io import BytesIO

# ================ CONFIGURATION ================
TSV_GZ_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
UPDATE_INTERVAL = 2  # Seconds between stats updates
RAM_SAFETY_MARGIN = 0.65  # 65% of available RAM
MIN_BATCH_SIZE = 10000
MAX_BATCH_SIZE = 100000
MAX_WORKERS = min(4, cpu_count())  # Conservative worker count

# ================ STABILITY CONTROLS ================
class StabilityManager:
    def __init__(self):
        self.last_ram_check = time.time()
        self.last_cpu_check = time.time()
        self.safe_mode = False
        self.restart_count = 0
        self.max_restarts = 3
        
    def check_system_health(self):
        """Evaluate system conditions and adjust operations"""
        current_time = time.time()
        
        # Check RAM every 15 seconds
        if current_time - self.last_ram_check > 15:
            ram = psutil.virtual_memory()
            if ram.percent > 90:
                print("\n⚠️  High RAM usage, activating safe mode")
                self.safe_mode = True
            elif ram.percent < 70 and self.safe_mode:
                print("\n✅ RAM normalized, exiting safe mode")
                self.safe_mode = False
            self.last_ram_check = current_time
        
        # Check CPU every 30 seconds
        if current_time - self.last_cpu_check > 30:
            cpu = psutil.cpu_percent(interval=1)
            if cpu > 90:
                print("\n⚠️  High CPU load, throttling operations")
                time.sleep(2)  # Brief cooldown
            self.last_cpu_check = current_time
        
        return not self.safe_mode  # Returns True if normal operations can continue

# ================ RESILIENT WORKER SYSTEM ================
def resilient_worker(batch, targets, worker_id):
    """Worker process with built-in recovery"""
    results = []
    start_time = time.time()
    
    try:
        for i, pk in enumerate(batch):
            # Memory check
            if i % 1000 == 0 and psutil.virtual_memory().percent > 95:
                print(f"\nWorker {worker_id}: High RAM, skipping batch")
                return []
                
            # Process key
            sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
            x = sk.verifying_key.pubkey.point.x()
            y = sk.verifying_key.pubkey.point.y()
            pubkey = (b'\x03' if y % 2 else b'\x02') + x.to_bytes(32, 'big')
            h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
            addr = base58.b58encode_check(b'\x00' + h160).decode()
            
            if addr in targets:
                wif = base58.b58encode_check(b'\x80' + pk + b'\x01').decode()
                results.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|{addr}|{wif}\n")
                
            # Yield control periodically
            if i % 500 == 0:
                time.sleep(0.001)
                
    except Exception as e:
        print(f"\nWorker {worker_id} error: {str(e)}")
        return []
    
    return results

# ================ MAIN CONTROLLER ================
def main_loop():
    """Primary scanning loop with recovery mechanisms"""
    stability = StabilityManager()
    manager = Manager()
    
    # Load targets first
    print("\n🔍 Loading address database...")
    try:
        response = requests.get(TSV_GZ_URL, stream=True, timeout=60)
        response.raise_for_status()
        
        targets = set()
        with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
            for line in f:
                try:
                    addr = line.decode().split('\t')[0]
                    if 26 <= len(addr) <= 35:
                        targets.add(addr)
                except:
                    continue
                
                # Early exit if memory is constrained
                if psutil.virtual_memory().percent > 90:
                    print("\n⚠️  Memory limit reached during load")
                    break
        
        print(f"✅ Loaded {len(targets):,} addresses")
        
    except Exception as e:
        print(f"\n❌ Failed to load targets: {str(e)}")
        return False

    # Initialize shared resources
    stats = manager.dict({
        'total': 0,
        'speed': 0,
        'found': 0,
        'start_time': time.time()
    })
    result_queue = manager.Queue()
    
    # Worker pool with limited retries
    with Pool(MAX_WORKERS) as pool:
        try:
            batch_count = 0
            last_display = time.time()
            
            while stability.restart_count < stability.max_restarts:
                if not stability.check_system_health():
                    time.sleep(5)  # Wait if in safe mode
                    continue
                    
                # Dynamic batch sizing
                batch_size = MIN_BATCH_SIZE if stability.safe_mode else MAX_BATCH_SIZE
                batch = [os.urandom(32) for _ in range(batch_size)]
                
                # Process batch
                pool.apply_async(
                    resilient_worker,
                    args=(batch, targets, batch_count % MAX_WORKERS),
                    callback=lambda r: (
                        result_queue.put(r),
                        stats.update({'found': stats['found'] + len(r)})
                    ) if r else None
                )
                
                # Update stats
                stats['total'] += batch_size
                stats['speed'] = batch_size / (time.time() - stats.get('last_batch_time', time.time()))
                stats['last_batch_time'] = time.time()
                batch_count += 1
                
                # Display progress
                if time.time() - last_display > UPDATE_INTERVAL:
                    ram = psutil.virtual_memory()
                    elapsed = time.time() - stats['start_time']
                    print(
                        f"\r🌀 Keys: {stats['total']:,} | "
                        f"Speed: {stats['speed']/1000:,.1f}K/s | "
                        f"Found: {stats['found']} | "
                        f"RAM: {ram.percent}% | "
                        f"Workers: {MAX_WORKERS}",
                        end="", flush=True
                    )
                    last_display = time.time()
                
                # Save results
                if not result_queue.empty():
                    with open("found.txt", "a") as f:
                        while not result_queue.empty():
                            f.writelines(result_queue.get())
                
                # Gentle sleep to prevent CPU hogging
                time.sleep(0.1)
                
        except Exception as e:
            print(f"\n⚠️  Main loop error: {str(e)}")
            stability.restart_count += 1
            return False
            
        finally:
            print("\n🔁 Cleaning up workers...")
            pool.close()
            pool.join()
            
            # Final save
            with open("found.txt", "a") as f:
                while not result_queue.empty():
                    f.writelines(result_queue.get())
    
    return True

# ================ LIFECYCLE MANAGEMENT ================
def signal_handler(sig, frame):
    print("\n🛑 Shutdown signal received")
    sys.exit(0)

if __name__ == "__main__":
    # Handle termination signals
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Clean restart mechanism
    if '--clean' not in sys.argv:
        os.execv(sys.executable, [sys.executable] + sys.argv + ['--clean'])
    
    # Main execution with restart capability
    success = main_loop()
    
    # Final report
    if success:
        print("\n✅ Scan completed successfully")
    else:
        print("\n⚠️  Scan ended with warnings")
    
    print("Results saved to found.txt")
