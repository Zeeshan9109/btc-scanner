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
UPDATE_INTERVAL = 3  # Seconds between stats updates
RAM_USAGE_TARGET = 0.75  # Target RAM usage ratio (75%)
MIN_BATCH_SIZE = 25000
MAX_BATCH_SIZE = 150000
MAX_WORKERS = min(8, cpu_count())  # Never exceed 8 workers

# ================ SYSTEM OPTIMIZATION ================
def optimize_system():
    """Tune system parameters for best performance"""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
    except:
        pass

    if os.name == 'posix':
        try:
            os.nice(-10)  # Higher priority on Unix systems
        except:
            pass

# ================ RESOURCE MANAGEMENT ================
class ResourceManager:
    def __init__(self):
        self.last_ram_check = time.time()
        self.last_batch_size = MIN_BATCH_SIZE
        
    def get_optimal_batch_size(self):
        """Dynamically adjust batch size based on system resources"""
        # Only check RAM every few seconds to reduce overhead
        if time.time() - self.last_ram_check < 10:
            return self.last_batch_size
            
        available_ram = psutil.virtual_memory().available
        target_ram = available_ram * RAM_USAGE_TARGET
        bytes_per_key = 50  # Conservative estimate
        
        # Calculate new batch size
        new_size = min(
            MAX_BATCH_SIZE,
            max(MIN_BATCH_SIZE, int(target_ram / bytes_per_key))
        )
        
        # Smooth transitions between size changes
        if abs(new_size - self.last_batch_size) > MIN_BATCH_SIZE:
            self.last_batch_size = new_size
        
        self.last_ram_check = time.time()
        return self.last_batch_size

# ================ CORE FUNCTIONS ================
def load_targets():
    """Load address database with memory monitoring"""
    print("\n🔍 Loading address database...")
    start_time = time.time()
    mem_before = psutil.virtual_memory().used
    
    try:
        response = requests.get(TSV_GZ_URL, stream=True, timeout=60)
        response.raise_for_status()
        
        targets = set()
        with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
            for i, line in enumerate(f):
                try:
                    addr = line.decode().split('\t')[0]
                    if 26 <= len(addr) <= 35:  # Basic validation
                        targets.add(addr)
                except:
                    continue
                
                # Periodic progress updates
                if i % 1000000 == 0:
                    elapsed = time.time() - start_time
                    mem_used = (psutil.virtual_memory().used - mem_before) / (1024**2)
                    speed = (i+1) / elapsed if elapsed > 0 else 0
                    print(
                        f"\r  Progress: {i//1000000}M lines | "
                        f"Speed: {speed/1000:,.1f}k lines/sec | "
                        f"RAM: {mem_used:,.1f}MB",
                        end="", flush=True
                    )
                    
                    # Memory safety check
                    if psutil.virtual_memory().percent > 90:
                        print("\n⚠️  Approaching memory limit, stopping load early")
                        break
        
        print(f"\n✅ Loaded {len(targets):,} addresses")
        return targets
    
    except Exception as e:
        print(f"\n❌ Failed to load database: {str(e)}")
        raise

def worker_process(batch, targets):
    """Optimized scanning process with error handling"""
    results = []
    start_time = time.time()
    
    for pk in batch:
        try:
            # Address generation
            sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
            x = sk.verifying_key.pubkey.point.x()
            y = sk.verifying_key.pubkey.point.y()
            pubkey = (b'\x03' if y % 2 else b'\x02') + x.to_bytes(32, 'big')
            h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
            addr = base58.b58encode_check(b'\x00' + h160).decode()
            
            # Check match
            if addr in targets:
                wif = base58.b58encode_check(b'\x80' + pk + b'\x01').decode()
                results.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|{addr}|{wif}\n")
        except Exception as e:
            continue
    
    return results

# ================ DISPLAY SYSTEM ================
class Dashboard:
    def __init__(self):
        self.start_time = time.time()
        self.last_update = time.time()
        self.last_found = None
        
    def update(self, stats):
        """Display real-time statistics"""
        current_time = time.time()
        if current_time - self.last_update < UPDATE_INTERVAL:
            return
            
        elapsed = current_time - self.start_time
        ram = psutil.virtual_memory()
        
        # Clear previous output
        print("\033[2J\033[H", end="")  # ANSI escape codes
        
        # Display header
        print(f"""
┌────────────────────────────────────────────────────────────┐
│ Bitcoin Address Scanner - Professional Edition             │
├────────────────────────────────────────────────────────────┤
│ Started: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')} │
│ Running: {elapsed//3600:02.0f}:{(elapsed%3600)//60:02.0f}:{elapsed%60:02.0f} │ Workers: {stats['workers']} │
└────────────────────────────────────────────────────────────┘
""")
        
        # Main stats
        print(f"""
┌─────────────────┬──────────────────┬──────────────────┬─────────────────┐
│ Total Checked   │ Current Speed    │ Avg Speed        │ RAM Usage       │
├─────────────────┼──────────────────┼──────────────────┼─────────────────┤
│ {stats['total']:>15,} │ {stats['speed']:>16,.0f}/s │ {stats['total']/elapsed:>15,.0f}/s │ {ram.percent:>14}% │
└─────────────────┴──────────────────┴──────────────────┴─────────────────┘
""")
        
        # Found addresses
        if self.last_found:
            print(f"""
┌────────────────────────────────────────────────────────────┐
│ Last Found: {self.last_found} │
└────────────────────────────────────────────────────────────┘
""")
        
        self.last_update = current_time

# ================ MAIN CONTROLLER ================
def main():
    optimize_system()
    resource_mgr = ResourceManager()
    dashboard = Dashboard()
    
    print("Initializing Bitcoin scanner...")
    targets = load_targets()
    if not targets:
        print("No targets loaded - exiting")
        return
    
    with Manager() as manager:
        stats = manager.dict({
            'total': 0,
            'speed': 0,
            'workers': MAX_WORKERS,
            'found': 0
        })
        result_queue = manager.Queue()
        
        with Pool(MAX_WORKERS) as pool:
            try:
                print(f"\n🚀 Starting scan with {MAX_WORKERS} workers")
                batch_count = 0
                
                while True:
                    # Get dynamic batch size
                    batch_size = resource_mgr.get_optimal_batch_size()
                    batch = [os.urandom(32) for _ in range(batch_size)]
                    
                    # Process batch
                    pool.apply_async(
                        worker_process,
                        args=(batch, targets),
                        callback=lambda r: (
                            result_queue.put(r),
                            stats.update({'found': stats['found'] + len(r)}),
                            setattr(dashboard, 'last_found', datetime.now().strftime('%Y-%m-%d %H:%M:%S')) if r else None
                        )
                    )
                    
                    # Update statistics
                    stats['total'] += batch_size
                    stats['speed'] = batch_size / (time.time() - stats.get('last_batch_time', time.time()))
                    stats['last_batch_time'] = time.time()
                    batch_count += 1
                    
                    # Update display
                    dashboard.update(dict(stats))
                    
                    # Save results
                    if not result_queue.empty():
                        with open("found.txt", "a") as f:
                            while not result_queue.empty():
                                f.writelines(result_queue.get())
                    
                    # Smooth operation throttle
                    time.sleep(max(0, UPDATE_INTERVAL - (time.time() - stats['last_batch_time'])))
                    
            except KeyboardInterrupt:
                print("\n🛑 Shutting down workers...")
                pool.close()
                pool.join()
                
                # Final save
                with open("found.txt", "a") as f:
                    while not result_queue.empty():
                        f.writelines(result_queue.get())
                
                # Final report
                total_time = time.time() - dashboard.start_time
                print(f"""
┌────────────────────────────────────────────────────────────┐
│ Scan Summary                                               │
├────────────────────────────────────────────────────────────┤
│ Runtime:    {total_time//3600:02.0f}:{(total_time%3600)//60:02.0f}:{total_time%60:02.0f}                 │
│ Keys:       {stats['total']:,}                            │
│ Speed:      {stats['total']/total_time:,.0f}/s             │
│ Found:      {stats['found']}                              │
└────────────────────────────────────────────────────────────┘
""")

if __name__ == "__main__":
    # Clean restart mechanism
    if '--clean' not in sys.argv:
        os.execv(sys.executable, [sys.executable] + sys.argv + ['--clean'])
    main()
