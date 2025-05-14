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

# ================ VISUAL CONFIG ================
class ScannerDisplay:
    def __init__(self):
        self.last_worker_update = time.time()
        self.worker_stats = {}
    
    def print_header(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""\033[1;36m
╔════════════════════════════════════════════════════════╗
║ \033[1;33mBITCOIN ADDRESS SCANNER - PROFESSIONAL EDITION\033[1;36m  ║
╠════════════════════════════════════════════════════════╣
║ \033[0;37mRunning on GitHub Codespaces | Cores: {}\033[1;36m        ║
╚════════════════════════════════════════════════════════╝\033[0m
""".format(cpu_count()))

    def update_dashboard(self, stats, found_count):
        ram = psutil.virtual_memory()
        elapsed = time.time() - stats['start_time']
        
        print(f"""\033[1;34m
┌─────────────────┬──────────────────┬──────────────────┬─────────────────┐
│ \033[1;32mTotal Checked\033[1;34m │ \033[1;32mCurrent Speed\033[1;34m   │ \033[1;32mAvg Speed\033[1;34m      │ \033[1;32mRAM Usage\033[1;34m    │
├─────────────────┼──────────────────┼──────────────────┼─────────────────┤
│ \033[0;37m{stats['total']:>15,}\033[1;34m │ \033[0;37m{stats['speed']:>16,.0f}/s\033[1;34m │ \033[0;37m{(stats['total']/elapsed):>15,.0f}/s\033[1;34m │ \033[0;37m{ram.percent:>14}%\033[1;34m │
└─────────────────┴──────────────────┴──────────────────┴─────────────────┘

┌─────────────────┬──────────────────┬──────────────────┬─────────────────┐
│ \033[1;32mRunning Time\033[1;34m  │ \033[1;32mAddresses Found\033[1;34m │ \033[1;32mLast Found\033[1;34m    │ \033[1;32mWorkers Active\033[1;34m │
├─────────────────┼──────────────────┼──────────────────┼─────────────────┤
│ \033[0;37m{datetime.fromtimestamp(stats['start_time']).strftime('%H:%M:%S'):>15}\033[1;34m │ \033[0;37m{found_count:>16}\033[1;34m │ \033[0;37m{stats.get('last_found', 'Never'):>16}\033[1;34m │ \033[0;37m{len(self.worker_stats):>14}/{cpu_count()}\033[1;34m │
└─────────────────┴──────────────────┴──────────────────┴─────────────────┘
\033[0m""")

        if self.worker_stats:
            print("\033[1;35m├─────────────── WORKER DETAILS ──────────────────────────────┤\033[0m")
            for pid, info in self.worker_stats.items():
                print(f"""\033[1;34m│ \033[1;33mWorker {pid}\033[1;34m │ Speed: \033[0;37m{info['speed']:,.0f}/s\033[1;34m │ Progress: \033[0;37m{info['progress']}\033[1;34m │ Last Update: \033[0;37m{info['last_update']}\033[1;34m │\033[0m""")
            print("\033[1;35m└────────────────────────────────────────────────────────────┘\033[0m")

    def found_alert(self, address, wif, balance):
        print(f"""\033[1;32m
╔════════════════════════════════════════════════════════╗
║ \033[1;31m•!• MATCH FOUND •!•\033[1;32m                                  ║
╠════════════════════════════════════════════════════════╣
║ \033[0;37mAddress: {address[:10]}...{address[-10:]}\033[1;32m             ║
║ \033[0;37mWIF: {wif[:10]}...{wif[-10:]}\033[1;32m                        ║
║ \033[0;37mBalance: {balance:,} satoshis\033[1;32m                        ║
║ \033[0;37mTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[1;32m ║
╚════════════════════════════════════════════════════════╝
\033[0m""")

# ================ CORE FUNCTIONS ================
def load_targets():
    print("\033[1;34m\n[•] Loading address database...\033[0m")
    response = requests.get(TSV_GZ_URL, stream=True)
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
    
    print(f"\033[1;32m[✓] Loaded {len(targets):,} addresses\033[0m")
    return targets

def worker_process(batch, targets, worker_id):
    results = []
    start_time = time.time()
    
    for i, pk in enumerate(batch):
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
            results.append((addr, wif))
        
        # Worker stats update
        if time.time() - start_time > 1:  # Update every second
            current_speed = (i + 1) / (time.time() - start_time)
            worker_stats[worker_id] = {
                'speed': current_speed,
                'progress': f"{i+1}/{len(batch)}",
                'last_update': datetime.now().strftime('%H:%M:%S')
            }
            start_time = time.time()
    
    return results

# ================ MAIN CONTROLLER ================
def main():
    display = ScannerDisplay()
    display.print_header()
    
    targets = load_targets()
    if not targets:
        print("\033[1;31m[×] No targets loaded - exiting\033[0m")
        return
    
    with Manager() as manager:
        stats = manager.dict({
            'total': 0,
            'speed': 0,
            'start_time': time.time(),
            'last_found': None
        })
        found_count = manager.Value('i', 0)
        
        # Worker communication
        global worker_stats
        worker_stats = manager.dict()
        
        with Pool(cpu_count()) as pool:
            try:
                batch_size = 50000
                batch_count = 0
                
                while True:
                    # Submit new batch
                    batch = [os.urandom(32) for _ in range(batch_size)]
                    pool.apply_async(
                        worker_process,
                        args=(batch, targets, batch_count % cpu_count()),
                        callback=lambda r: (
                            found_count.set(found_count.value + len(r)),
                            stats.update({'last_found': datetime.now().strftime('%H:%M:%S')}),
                            [display.found_alert(addr, wif, 0) for addr, wif in r]
                        ) if r else None
                    )
                    
                    # Update stats
                    stats['total'] += len(batch)
                    stats['speed'] = len(batch) / (time.time() - stats.get('last_batch_time', time.time()))
                    stats['last_batch_time'] = time.time()
                    batch_count += 1
                    
                    # Update display
                    display.update_dashboard(stats, found_count.value)
                    
                    # Save results
                    time.sleep(1)  # Throttle display updates
                    
            except KeyboardInterrupt:
                print("\n\033[1;33m[!] Shutting down workers...\033[0m")
                pool.close()
                pool.join()
                
                # Final report
                elapsed = time.time() - stats['start_time']
                print(f"""\033[1;36m
╔════════════════════════════════════════════════════════╗
║                    SCAN SUMMARY                        ║
╠════════════════════════════════════════════════════════╣
║ \033[1;33mTotal Runtime:\033[0m {elapsed/3600:.2f} hours                 ║
║ \033[1;33mKeys Checked:\033[0m {stats['total']:,}                      ║
║ \033[1;33mAverage Speed:\033[0m {stats['total']/elapsed:,.0f}/s        ║
║ \033[1;33mAddresses Found:\033[0m {found_count.value}                 ║
╚════════════════════════════════════════════════════════╝
\033[0m""")

if __name__ == "__main__":
    main()
