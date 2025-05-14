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

# ================ VERSION CONTROL ================
SCRIPT_VERSION = "2.3.1"
LAST_MODIFIED = os.path.getmtime(__file__)

# ================ CONFIGURATION ================
TSV_GZ_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
UPDATE_INTERVAL = 5  # Seconds between stats updates
MAX_RAM_USAGE = 0.8  # 80% of available RAM
MIN_BATCH_SIZE = 50000
MAX_BATCH_SIZE = 500000

# ================ DISPLAY SYSTEM ================
class TerminalDisplay:
    COLORS = {
        'header': '\033[1;36m',
        'success': '\033[1;32m',
        'error': '\033[1;31m',
        'warning': '\033[1;33m',
        'info': '\033[1;34m',
        'reset': '\033[0m'
    }

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_header(self, cores):
        self.clear_screen()
        print(f"""{self.COLORS['header']}
╔════════════════════════════════════════════════════════╗
║ {self.COLORS['warning']}BITCOIN ADDRESS SCANNER v{SCRIPT_VERSION}{self.COLORS['header']}              ║
╠════════════════════════════════════════════════════════╣
║ {self.COLORS['info']}GitHub Codespaces | {cores} Cores | {datetime.now().strftime('%Y-%m-%d')}{self.COLORS['header']} ║
╚════════════════════════════════════════════════════════╝{self.COLORS['reset']}""")

    def show_stats(self, stats, found_count, worker_info):
        ram = psutil.virtual_memory()
        elapsed = time.time() - stats['start_time']
        
        print(f"""{self.COLORS['info']}
┌─────────────────┬──────────────────┬──────────────────┬─────────────────┐
│ {self.COLORS['success']}Total Checked{self.COLORS['info']} │ {self.COLORS['success']}Current Speed{self.COLORS['info']}   │ {self.COLORS['success']}Avg Speed{self.COLORS['info']}      │ {self.COLORS['success']}RAM Usage{self.COLORS['info']}    │
├─────────────────┼──────────────────┼──────────────────┼─────────────────┤
│ {self.COLORS['reset']}{stats['total']:>15,}{self.COLORS['info']} │ {self.COLORS['reset']}{stats['speed']:>16,.0f}/s{self.COLORS['info']} │ {self.COLORS['reset']}{(stats['total']/elapsed):>15,.0f}/s{self.COLORS['info']} │ {self.COLORS['reset']}{ram.percent:>14}%{self.COLORS['info']} │
└─────────────────┴──────────────────┴──────────────────┴─────────────────┘

┌─────────────────┬──────────────────┬──────────────────┬─────────────────┐
│ {self.COLORS['success']}Running Time{self.COLORS['info']}  │ {self.COLORS['success']}Addresses Found{self.COLORS['info']} │ {self.COLORS['success']}Last Found{self.COLORS['info']}    │ {self.COLORS['success']}Workers Active{self.COLORS['info']} │
├─────────────────┼──────────────────┼──────────────────┼─────────────────┤
│ {self.COLORS['reset']}{datetime.fromtimestamp(stats['start_time']).strftime('%H:%M:%S'):>15}{self.COLORS['info']} │ {self.COLORS['reset']}{found_count:>16}{self.COLORS['info']} │ {self.COLORS['reset']}{stats.get('last_found', 'Never'):>16}{self.COLORS['info']} │ {self.COLORS['reset']}{len(worker_info):>14}/{cpu_count()}{self.COLORS['info']} │
└─────────────────┴──────────────────┴──────────────────┴─────────────────┘
{self.COLORS['warning']}┌─────────────────────── WORKER DETAILS ───────────────────────┐{self.COLORS['reset']}""")

        for pid, info in worker_info.items():
            print(f"""{self.COLORS['info']}│ {self.COLORS['warning']}Worker {pid}{self.COLORS['info']} │ Speed: {self.COLORS['reset']}{info['speed']:,.0f}/s{self.COLORS['info']} │ Progress: {self.COLORS['reset']}{info['progress']}{self.COLORS['info']} │ Last: {self.COLORS['reset']}{info['last_update']}{self.COLORS['info']} │{self.COLORS['reset']}""")

        print(f"""{self.COLORS['warning']}└────────────────────────────────────────────────────────────┘{self.COLORS['reset']}""")

    def found_alert(self, address, wif):
        print(f"""{self.COLORS['success']}
╔════════════════════════════════════════════════════════╗
║ {self.COLORS['warning']}•!• MATCH FOUND •!•{self.COLORS['success']}                                  ║
╠════════════════════════════════════════════════════════╣
║ {self.COLORS['reset']}Address: {address[:10]}...{address[-10:]}{self.COLORS['success']}               ║
║ {self.COLORS['reset']}WIF: {wif[:10]}...{wif[-10:]}{self.COLORS['success']}                          ║
║ {self.COLORS['reset']}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{self.COLORS['success']}   ║
╚════════════════════════════════════════════════════════╝
{self.COLORS['reset']}""")

# ================ CORE FUNCTIONS ================
def calculate_batch_size():
    """Dynamically adjust batch size based on available RAM"""
    avail_ram = psutil.virtual_memory().available
    return min(
        MAX_BATCH_SIZE,
        max(MIN_BATCH_SIZE, int(avail_ram * MAX_RAM_USAGE / 34))  # 34 bytes per key
    )

def load_targets():
    """Load address database with progress tracking"""
    display = TerminalDisplay()
    display.clear_screen()
    print(f"{display.COLORS['info']}\n[•] Loading address database...{display.COLORS['reset']}")
    
    try:
        response = requests.get(TSV_GZ_URL, stream=True, timeout=30)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        
        targets = set()
        processed_bytes = 0
        start_time = time.time()
        
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
                
                # Progress display
                elapsed = time.time() - start_time
                speed = processed_bytes / elapsed if elapsed > 0 else 0
                print(
                    f"\r{display.COLORS['info']}[•] Progress: "
                    f"{processed_bytes/(1024**2):.1f}MB/{total_size/(1024**2):.1f}MB | "
                    f"Speed: {speed/(1024**2):.1f}MB/s | "
                    f"Addresses: {len(targets):,}{display.COLORS['reset']}",
                    end="", flush=True
                )
        
        print(f"\n{display.COLORS['success']}[✓] Loaded {len(targets):,} addresses{display.COLORS['reset']}")
        return targets
    
    except Exception as e:
        print(f"\n{display.COLORS['error']}[×] Failed to load database: {str(e)}{display.COLORS['reset']}")
        raise

def worker_process(batch, targets, worker_id):
    """Optimized scanning process with detailed metrics"""
    results = []
    start_time = time.time()
    processed = 0
    batch_size = len(batch)
    
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
            results.append((addr, wif))
        
        processed += 1
        if processed % 10000 == 0 or processed == batch_size:
            current_speed = processed / (time.time() - start_time)
            worker_stats[worker_id] = {
                'speed': current_speed,
                'progress': f"{processed}/{batch_size}",
                'last_update': datetime.now().strftime('%H:%M:%S')
            }
    
    return results

# ================ MAIN CONTROLLER ================
def main():
    # Force clean start
    if '--clean' not in sys.argv:
        os.system('pkill -f "python scanner.py"')
        os.execv(sys.executable, [sys.executable] + sys.argv + ['--clean'])
    
    # Initialize systems
    display = TerminalDisplay()
    display.show_header(cpu_count())
    
    print(f"{display.COLORS['info']}[•] Script modified: {datetime.fromtimestamp(LAST_MODIFIED)}{display.COLORS['reset']}")
    print(f"{display.COLORS['info']}[•] Initializing scanner...{display.COLORS['reset']}")
    
    # Load targets
    targets = load_targets()
    if not targets:
        print(f"{display.COLORS['error']}[×] No targets loaded - exiting{display.COLORS['reset']}")
        return
    
    with Manager() as manager:
        # Shared statistics
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
                batch_count = 0
                display.show_header(cpu_count())
                
                while True:
                    # Generate and process batch
                    batch_size = calculate_batch_size()
                    batch = [os.urandom(32) for _ in range(batch_size)]
                    
                    pool.apply_async(
                        worker_process,
                        args=(batch, targets, batch_count % cpu_count()),
                        callback=lambda r: (
                            found_count.set(found_count.value + len(r)),
                            stats.update({'last_found': datetime.now().strftime('%H:%M:%S')}),
                            [display.found_alert(addr, wif) for addr, wif in r]
                        ) if r else None
                    )
                    
                    # Update statistics
                    stats['total'] += batch_size
                    stats['speed'] = batch_size / (time.time() - stats.get('last_batch_time', time.time()))
                    stats['last_batch_time'] = time.time()
                    batch_count += 1
                    
                    # Update display
                    display.show_stats(stats, found_count.value, dict(worker_stats))
                    
                    # Throttle updates
                    time.sleep(max(0, UPDATE_INTERVAL - (time.time() - stats['last_batch_time'])))
                    
            except KeyboardInterrupt:
                print(f"\n{display.COLORS['warning']}[!] Shutting down workers...{display.COLORS['reset']}")
                pool.close()
                pool.join()
                
                # Final report
                elapsed = time.time() - stats['start_time']
                print(f"""{display.COLORS['header']}
╔════════════════════════════════════════════════════════╗
║ {display.COLORS['warning']}SCAN SUMMARY{display.COLORS['header']}                                      ║
╠════════════════════════════════════════════════════════╣
║ {display.COLORS['info']}Total Runtime:{display.COLORS['reset']} {elapsed/3600:.2f} hours                 ║
║ {display.COLORS['info']}Keys Checked:{display.COLORS['reset']} {stats['total']:,}                      ║
║ {display.COLORS['info']}Average Speed:{display.COLORS['reset']} {stats['total']/elapsed:,.0f}/s        ║
║ {display.COLORS['info']}Addresses Found:{display.COLORS['reset']} {found_count.value}                 ║
║ {display.COLORS['info']}Last Modified:{display.COLORS['reset']} {datetime.fromtimestamp(LAST_MODIFIED)} ║
╚════════════════════════════════════════════════════════╝
{display.COLORS['reset']}""")

if __name__ == "__main__":
    main()
