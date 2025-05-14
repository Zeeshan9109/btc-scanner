#!/usr/bin/env python3
import os
import gzip
import random
import hashlib
import base58
import requests
import multiprocessing
from tqdm import tqdm
import time
import bisect
import sys
import signal
from typing import List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class Config:
    ADDRESS_FILE_URL: str = "YOUR_DIRECT_DOWNLOAD_LINK_HERE.tsv.gz"
    DOWNLOAD_PATH: str = "/tmp/addresses.tsv.gz"  # Using /tmp for better performance in Codespaces
    FOUND_FILE: str = "found.txt"
    THREADS: int = max(multiprocessing.cpu_count() * 2, 8)
    INITIAL_BATCH_SIZE: int = 100000
    MAX_BATCH_SIZE: int = 500000
    MIN_BATCH_SIZE: int = 10000
    STATS_INTERVAL: float = 2.0
    PROGRESS_INTERVAL: float = 0.5
    TARGET_SPEED: int = 5000000
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 5.0
    CHUNK_SIZE: int = 8192

class BitcoinScanner:
    def __init__(self):
        self.cfg = Config()
        self.address_list: List[str] = []
        self.balance_list: List[int] = []
        
        # ECC constants
        self.secp256k1_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.secp256k1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        self.secp256k1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        self.secp256k1_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        # State management
        self.start_time: float = 0
        self.total_checked: int = 0
        self.found_count: int = 0
        self.current_speed: float = 0
        self.shutdown_flag = multiprocessing.Event()
        
        # Setup graceful shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\nReceived shutdown signal {signum}, terminating...")
        self.shutdown_flag.set()

    def _init_ripemd160(self):
        """Initialize RIPEMD-160 with multiple fallback options"""
        try:
            h = hashlib.new('ripemd160')
            h.update(b'')
            return h
        except ValueError:
            try:
                # Try pycryptodome if available
                from Crypto.Hash import RIPEMD160
                return RIPEMD160.new()
            except ImportError:
                try:
                    # Fallback to pure Python implementation
                    from ripemd import RIPEMD160Hash
                    return RIPEMD160Hash()
                except ImportError:
                    raise RuntimeError("No working RIPEMD-160 implementation found")

    def private_key_to_address(self, private_key: bytes) -> Optional[str]:
        """Optimized address generation with validation"""
        if len(private_key) != 32:
            return None
            
        d = int.from_bytes(private_key, 'big')
        if not (1 <= d < self.secp256k1_n):
            return None
            
        try:
            Qx, Qy = self._ecc_point_mul(d)
            pubkey = bytes([0x02 + (Qy % 2)]) + Qx.to_bytes(32, 'big')
            sha256 = hashlib.sha256(pubkey).digest()
            
            ripemd160 = self._init_ripemd160()
            ripemd160.update(sha256)
            hash160 = ripemd160.digest()
            
            version = b'\x00'
            checksum = hashlib.sha256(hashlib.sha256(version + hash160).digest()).digest()[:4]
            return base58.b58encode(version + hash160 + checksum).decode('utf-8')
        except:
            return None

    def _ecc_point_mul(self, d: int) -> Tuple[int, int]:
        """Optimized elliptic curve multiplication using NAF"""
        Qx, Qy = None, None
        for i in reversed(range(256)):
            if Qx is not None:
                # Point doubling
                l = (3 * Qx * Qx) * pow(2 * Qy, self.secp256k1_p-2, self.secp256k1_p) % self.secp256k1_p
                Qx = (l*l - 2*Qx) % self.secp256k1_p
                Qy = (l*(Qx - (l*l - 2*Qx)) - Qy) % self.secp256k1_p
            if d & (1 << i):
                if Qx is None:
                    Qx, Qy = self.secp256k1_Gx, self.secp256k1_Gy
                else:
                    # Point addition
                    l = (Qy - self.secp256k1_Gy) * pow(Qx - self.secp256k1_Gx, self.secp256k1_p-2, self.secp256k1_p) % self.secp256k1_p
                    Qx = (l*l - Qx - self.secp256k1_Gx) % self.secp256k1_p
                    Qy = (l*(self.secp256k1_Gx - Qx) - self.secp256k1_Gy) % self.secp256k1_p
        return Qx, Qy

    def generate_valid_private_key(self) -> bytes:
        """Thread-safe cryptographically secure key generation"""
        while not self.shutdown_flag.is_set():
            private_key = bytes([random.SystemRandom().getrandbits(8) for _ in range(32)])
            d = int.from_bytes(private_key, 'big')
            if 1 <= d < self.secp256k1_n:
                return private_key
        return b''  # Return empty on shutdown

    def worker(self, 
               task_queue: multiprocessing.Queue, 
               result_queue: multiprocessing.Queue,
               progress_queue: multiprocessing.Queue):
        """Worker process optimized for Codespaces"""
        try:
            while not self.shutdown_flag.is_set():
                try:
                    batch_size = task_queue.get(timeout=1)
                    if batch_size is None:
                        break
                        
                    found = []
                    checked = 0
                    for _ in range(batch_size):
                        if self.shutdown_flag.is_set():
                            break
                            
                        priv_key = self.generate_valid_private_key()
                        if not priv_key:
                            break
                            
                        address = self.private_key_to_address(priv_key)
                        checked += 1
                        
                        if address:
                            idx = bisect.bisect_left(self.address_list, address)
                            if idx < len(self.address_list) and self.address_list[idx] == address:
                                wif = base58.b58encode_check(b'\x80' + priv_key).decode('utf-8')
                                balance = self.balance_list[idx]
                                found.append((wif, address, balance))
                    
                    if found:
                        result_queue.put(found)
                    progress_queue.put(checked)
                except multiprocessing.TimeoutError:
                    continue
        except Exception as e:
            print(f"Worker error: {e}", file=sys.stderr)

    def download_address_file(self) -> bool:
        """Download with retries and progress, optimized for cloud"""
        if os.path.exists(self.cfg.DOWNLOAD_PATH):
            return True
            
        print("Downloading address file...")
        
        for attempt in range(self.cfg.MAX_RETRIES):
            try:
                with requests.get(self.cfg.ADDRESS_FILE_URL, stream=True, timeout=30) as r:
                    r.raise_for_status()
                    total_size = int(r.headers.get('content-length', 0))
                    
                    with open(self.cfg.DOWNLOAD_PATH, 'wb') as f, tqdm(
                        desc="Downloading",
                        total=total_size,
                        unit='B',
                        unit_scale=True,
                        unit_divisor=1024,
                    ) as bar:
                        for chunk in r.iter_content(chunk_size=self.cfg.CHUNK_SIZE):
                            if chunk:
                                f.write(chunk)
                                bar.update(len(chunk))
                return True
            except Exception as e:
                print(f"Attempt {attempt + 1} failed: {e}", file=sys.stderr)
                if attempt < self.cfg.MAX_RETRIES - 1:
                    time.sleep(self.cfg.RETRY_DELAY)
        return False

    def load_address_database(self) -> bool:
        """Load and sort addresses with memory efficiency"""
        if not self.download_address_file():
            return False
            
        print("Loading address database...")
        try:
            with gzip.open(self.cfg.DOWNLOAD_PATH, 'rt') as f:
                for line in tqdm(f, desc="Processing"):
                    if self.shutdown_flag.is_set():
                        return False
                        
                    try:
                        parts = line.strip().split('\t')
                        if len(parts) >= 2 and parts[0].startswith(('1', '3')):
                            address = parts[0].strip()
                            balance = int(float(parts[1]))
                            self.address_list.append(address)
                            self.balance_list.append(balance)
                    except (ValueError, IndexError):
                        continue
            
            # Sort for binary search
            sorted_indices = sorted(range(len(self.address_list)), key=lambda k: self.address_list[k])
            self.address_list = [self.address_list[i] for i in sorted_indices]
            self.balance_list = [self.balance_list[i] for i in sorted_indices]
            
            print(f"Loaded {len(self.address_list):,} addresses")
            return True
        except Exception as e:
            print(f"Database error: {e}", file=sys.stderr)
            return False

    def scan_addresses(self):
        """Main scanning loop with cloud optimizations"""
        if not self.load_address_database():
            return
            
        print(f"\nStarting scan with {self.cfg.THREADS} threads")
        print(f"Target speed: {self.cfg.TARGET_SPEED:,} addresses/sec\n")
        
        with multiprocessing.Manager() as manager:
            task_queue = manager.Queue()
            result_queue = manager.Queue()
            progress_queue = manager.Queue()
            
            workers = []
            for _ in range(self.cfg.THREADS):
                p = multiprocessing.Process(
                    target=self.worker,
                    args=(task_queue, result_queue, progress_queue),
                    daemon=True
                )
                p.start()
                workers.append(p)
            
            self.start_time = time.time()
            last_stats_time = self.start_time
            last_progress_update = self.start_time
            batch_size = self.cfg.INITIAL_BATCH_SIZE
            
            try:
                with tqdm(desc="Scanning", unit="addr", file=sys.stdout) as pbar:
                    while not self.shutdown_flag.is_set():
                        # Feed work to workers
                        task_queue.put(batch_size)
                        
                        # Process results and progress
                        processed = 0
                        while not result_queue.empty():
                            for wif, address, balance in result_queue.get():
                                with open(self.cfg.FOUND_FILE, 'a') as f:
                                    f.write(f"WIF: {wif}\nAddress: {address}\nBalance: {balance:,}\n\n")
                                self.found_count += 1
                                print(f"\nFound: {address} | Balance: {balance:,} sat")
                        
                        while not progress_queue.empty():
                            processed += progress_queue.get()
                        
                        if processed > 0:
                            self.total_checked += processed
                            pbar.update(processed)
                        
                        # Update stats
                        current_time = time.time()
                        if current_time - last_stats_time >= self.cfg.STATS_INTERVAL:
                            elapsed = current_time - self.start_time
                            self.current_speed = self.total_checked / elapsed if elapsed > 0 else 0
                            
                            # Dynamic batch sizing
                            if self.current_speed < self.cfg.TARGET_SPEED * 0.8:
                                batch_size = min(batch_size * 2, self.cfg.MAX_BATCH_SIZE)
                            elif self.current_speed > self.cfg.TARGET_SPEED * 1.2:
                                batch_size = max(batch_size // 2, self.cfg.MIN_BATCH_SIZE)
                            
                            last_stats_time = current_time
                        
                        # Update progress display
                        if current_time - last_progress_update >= self.cfg.PROGRESS_INTERVAL:
                            pbar.set_postfix({
                                'speed': f"{self.current_speed:,.0f}/sec",
                                'checked': f"{self.total_checked:,}",
                                'found': self.found_count,
                                'batch': batch_size
                            })
                            last_progress_update = current_time
                        
                        time.sleep(0.1)  # Reduce CPU usage
            finally:
                # Cleanup
                self.shutdown_flag.set()
                for _ in workers:
                    task_queue.put(None)
                
                for p in workers:
                    p.join(timeout=1)
                    if p.is_alive():
                        p.terminate()
                
                elapsed = time.time() - self.start_time
                print(f"\nScan completed")
                print(f"Total checked: {self.total_checked:,}")
                print(f"Total found: {self.found_count}")
                print(f"Average speed: {self.total_checked/elapsed:,.0f} addresses/sec")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    scanner = BitcoinScanner()
    scanner.scan_addresses()
