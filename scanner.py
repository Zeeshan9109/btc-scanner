import os
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

# ======================
#  CONFIGURATION
# ======================
TSV_GZ_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
UPDATE_INTERVAL = 5  # Seconds between stats updates
MAX_RAM_USAGE = 0.8  # Use 80% of available RAM
MIN_BATCH_SIZE = 50000
MAX_BATCH_SIZE = 500000

# ======================
#  SYSTEM OPTIMIZATION
# ======================
def optimize_system():
    """Tune system for maximum performance"""
    # Increase file descriptor limits
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
    
    # Set high priority (Linux/macOS)
    if hasattr(os, 'nice'):
        os.nice(-15)
    
    print("⚙️ System optimized for high-throughput scanning")

# ======================
#  CORE FUNCTIONS
# ======================
def calculate_dynamic_batch_size():
    """Dynamically scale batch size based on available RAM"""
    avail_ram = psutil.virtual_memory().available
    batch_size = min(
        MAX_BATCH_SIZE,
        max(MIN_BATCH_SIZE, int(avail_ram * MAX_RAM_USAGE / (34 * 1024))  # 34 bytes per key
    )
    return batch_size

def load_targets():
    """Load address database with detailed progress tracking"""
    print("\n📂 Loading address database...")
    mem_before = psutil.virtual_memory().used
    
    try:
        response = requests.get(TSV_GZ_URL, stream=True, timeout=30)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        
        targets = set()
        processed_bytes = 0
        last_update = time.time()
        
        with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
            while True:
                chunk = f.read(1024*1024)  # 1MB chunks
                if not chunk:
                    break
                
                processed_bytes += len(chunk)
                lines = chunk.split(b'\n')
                
                for line in lines:
                    try:
                        if b'\t' in line:
                            addr = line.decode().split('\t')[0]
                            if 26 <= len(addr) <= 35:
                                targets.add(addr)
                    except:
                        continue
                
                # Progress updates
                if time.time() - last_update > 2:
                    mem_used = (psutil.virtual_memory().used - mem_before) / (1024**2)
                    print(
                        f"\r🔍 Loading... | "
                        f"Progress: {processed_bytes/(1024**2):.1f}MB/{total_size/(1024**2):.1f}MB | "
                        f"Addresses: {len(targets):,} | "
                        f"RAM: {mem_used:.1f}MB",
                        end="", flush=True
                    )
                    last_update = time.time()
        
        print(f"\n✅ Successfully loaded {len(targets):,} addresses")
        return targets
    
    except Exception as e:
        print(f"\n❌ Failed to load database: {str(e)}")
        raise

def worker_process(batch, targets):
    """Optimized scanning with detailed metrics"""
    results = []
    start_time = time.time()
    processed = 0
    
    for pk in batch:
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
            results.append(f"{timestamp()}|{addr}|{wif}\n")
        
        processed += 1
        if processed % 10000 == 0:
            current_speed = processed / (time.time() - start_time)
            print(
                f"\r🔑 Worker {os.getpid()} | "
                f"Speed: {current_speed:,.0f} keys/sec | "
                f"Progress: {processed}/{len(batch)}",
                end="", flush=True
            )
    
    return results

# ======================
#  MAIN CONTROLLER
# ======================
def main():
    optimize_system()
    
    # Dynamic configuration
    WORKERS = cpu_count()
    BATCH_SIZE = calculate_dynamic_batch_size()
    
    print(f"""
🚀 Bitcoin Scanner - Professional Edition
=======================================
🔧 Configuration:
  • Cores: {WORKERS}
  • Batch Size: {BATCH_SIZE:,}
  • Max RAM Usage: {MAX_RAM_USAGE*100:.0f}%
  • Update Interval: {UPDATE_INTERVAL}s
=======================================
""")
    
    targets = load_targets()
    if not targets:
        print("❌ No targets loaded - exiting")
        return
    
    with Manager() as manager:
        result_queue = manager.Queue()
        stats = manager.dict({
            'total': 0,
            'speed': 0,
            'start_time': time.time(),
            'found': 0
        })
        
        with Pool(WORKERS) as pool:
            try:
                print("\n🔄 Starting scanning workers...\n")
                print("=" * 120)
                print(" Time        | Keys Checked  | Speed (keys/sec) | Workers Active | RAM Usage | Found | Current Batch Progress")
                print("=" * 120)
                
                last_update = time.time()
                batch_count = 0
                
                while True:
                    # Submit new batch
                    batch = [os.urandom(32) for _ in range(BATCH_SIZE)]
                    pool.apply_async(
                        worker_process,
                        args=(batch, targets),
                        callback=lambda r: (result_queue.put(r), stats.update({'found': stats['found'] + len(r)})) if r else None
                    )
                    
                    # Update stats
                    stats['total'] += len(batch)
                    batch_count += 1
                    
                    # Detailed stats display
                    if time.time() - last_update > UPDATE_INTERVAL:
                        elapsed = time.time() - stats['start_time']
                        ram = psutil.virtual_memory()
                        
                        print(
                            f"\r{timestamp()} | "
                            f"{stats['total']:,} | "
                            f"{stats['total']/elapsed:,.0f} | "
                            f"{len(pool._pool)}/{WORKERS} | "
                            f"{ram.percent}% | "
                            f"{stats['found']} | "
                            f"Batch #{batch_count}",
                            end="", flush=True
                        )
                        
                        # Adaptive batch sizing
                        new_batch_size = calculate_dynamic_batch_size()
                        if new_batch_size != BATCH_SIZE:
                            BATCH_SIZE = new_batch_size
                            print(f"\n🔄 Adjusted batch size to {BATCH_SIZE:,} based on RAM availability")
                        
                        last_update = time.time()
                    
                    # Save results
                    if not result_queue.empty():
                        with open("found.txt", "a") as f:
                            while not result_queue.empty():
                                f.writelines(result_queue.get())
                    
                    time.sleep(0.1)
                    
            except KeyboardInterrupt:
                print("\n\n🛑 Shutting down workers gracefully...")
                pool.close()
                pool.join()
                
                # Final save and report
                with open("found.txt", "a") as f:
                    while not result_queue.empty():
                        f.writelines(result_queue.get())
                
                total_time = time.time() - stats['start_time']
                print("\n" + "=" * 60)
                print("📊 FINAL SCAN REPORT")
                print("=" * 60)
                print(f"  Total Runtime:       {total_time/3600:.2f} hours")
                print(f"  Keys Checked:        {stats['total']:,}")
                print(f"  Average Speed:       {stats['total']/total_time:,.0f} keys/sec")
                print(f"  Peak Workers:        {WORKERS} cores")
                print(f"  Addresses Found:     {stats['found']}")
                print(f"  Results File:        found.txt")
                print("=" * 60)

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if __name__ == "__main__":
    main()
