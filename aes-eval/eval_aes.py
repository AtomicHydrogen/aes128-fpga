#!/usr/bin/env python3
"""
AES-128 FPGA Accelerator Benchmark Script

This script benchmarks an AES-128 hardware accelerator on a MicroBlaze FPGA
by sending test vectors over UART and measuring encryption time.

Protocol:
    TX: [16 bytes key] + [16 bytes plaintext] + [0xFF 0xFF] = 34 bytes
    RX: [16 bytes ciphertext] + [4 bytes cycle_count] = 20 bytes

Usage:
    Auto-detect:  python aes_benchmark.py --auto
    Windows:      python aes_benchmark.py --port COM3
    Linux:        python aes_benchmark.py --port /dev/ttyUSB1
    
    Image test:   python aes_benchmark.py --auto --image test.png
    List ports:   python aes_benchmark.py --list-ports

Requirements:
    pip install pyserial pycryptodome pillow
"""

import argparse
import time
import struct
import sys
import platform
import os
from typing import Optional, Tuple, List
import serial
import serial.tools.list_ports
from Crypto.Cipher import AES

# Optional: PIL for image processing
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def get_default_port() -> str:
    """Get default serial port based on OS."""
    if platform.system() == 'Windows':
        return 'COM3'
    elif platform.system() == 'Darwin':  # macOS
        return '/dev/tty.usbserial-0001'
    else:  # Linux
        return '/dev/ttyUSB1'


def list_serial_ports() -> List[Tuple[str, str]]:
    """List available serial ports on the system."""
    ports = serial.tools.list_ports.comports()
    return [(p.device, p.description) for p in ports]


def print_available_ports():
    """Print all available serial ports."""
    ports = list_serial_ports()
    if not ports:
        print("No serial ports found.")
    else:
        print("\nAvailable serial ports:")
        print("-" * 60)
        for device, description in ports:
            print(f"  {device:20s} - {description}")
        print("-" * 60)


class AESBenchmark:
    """AES-128 FPGA Accelerator Benchmark Class"""
    
    FRAME_MARKER = bytes([0xFF, 0xFF])
    KEY_SIZE = 16
    BLOCK_SIZE = 16
    TX_FRAME_SIZE = KEY_SIZE + BLOCK_SIZE + 2  # 34 bytes
    RX_FRAME_SIZE = BLOCK_SIZE + 4              # 20 bytes
    
    # NIST test vector for validation
    NIST_KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    NIST_PT = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
    NIST_CT = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')
    
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0):
        """Initialize serial connection to FPGA."""
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser: Optional[serial.Serial] = None
        
    def connect(self) -> bool:
        """Open serial connection."""
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=self.timeout
            )
            # Wait for FPGA to be ready
            time.sleep(0.3)
            # Flush any startup messages
            self.ser.reset_input_buffer()
            return True
        except serial.SerialException as e:
            return False
    
    def disconnect(self):
        """Close serial connection."""
        if self.ser and self.ser.is_open:
            self.ser.close()
    
    def encrypt_block(self, key: bytes, plaintext: bytes) -> Tuple[Optional[bytes], Optional[int]]:
        """
        Send key and plaintext to FPGA, receive ciphertext and cycle count.
        
        Args:
            key: 16-byte AES key
            plaintext: 16-byte plaintext block
            
        Returns:
            Tuple of (ciphertext, cycle_count) or (None, None) on error
        """
        if not self.ser or not self.ser.is_open:
            return None, None
        
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Plaintext must be {self.BLOCK_SIZE} bytes")
        
        # Build TX frame
        tx_frame = key + plaintext + self.FRAME_MARKER
        
        # Clear input buffer
        self.ser.reset_input_buffer()
        
        # Send frame
        self.ser.write(tx_frame)
        self.ser.flush()
        
        # Receive response
        rx_data = self.ser.read(self.RX_FRAME_SIZE)
        
        if len(rx_data) != self.RX_FRAME_SIZE:
            return None, None
        
        # Parse response
        ciphertext = rx_data[:self.BLOCK_SIZE]
        cycle_count = struct.unpack('<I', rx_data[self.BLOCK_SIZE:])[0]
        
        return ciphertext, cycle_count
    
    def validate_with_nist(self) -> bool:
        """Validate FPGA with NIST test vector. Returns True if valid."""
        ciphertext, _ = self.encrypt_block(self.NIST_KEY, self.NIST_PT)
        if ciphertext is None:
            return False
        return ciphertext == self.NIST_CT
    
    def verify_with_software(self, key: bytes, plaintext: bytes, 
                             hw_ciphertext: bytes) -> bool:
        """Verify hardware result against software AES."""
        cipher = AES.new(key, AES.MODE_ECB)
        sw_ciphertext = cipher.encrypt(plaintext)
        return hw_ciphertext == sw_ciphertext
    
    @classmethod
    def auto_detect(cls, baudrate: int = 115200, timeout: float = 1.0) -> Optional['AESBenchmark']:
        """
        Auto-detect FPGA by scanning all available serial ports.
        Tests each port with NIST test vector to verify AES accelerator.
        
        Returns:
            AESBenchmark instance if found, None otherwise
        """
        ports = list_serial_ports()
        
        if not ports:
            print("No serial ports found.")
            return None
        
        print(f"Scanning {len(ports)} serial port(s) for AES FPGA accelerator...")
        print("-" * 60)
        
        for device, description in ports:
            print(f"  Trying {device:20s} ({description[:30]})...", end=" ", flush=True)
            
            bench = cls(device, baudrate, timeout)
            if not bench.connect():
                print("FAILED (cannot open)")
                continue
            
            # Try NIST test vector
            try:
                if bench.validate_with_nist():
                    print("FOUND!")
                    print("-" * 60)
                    print(f"AES FPGA accelerator detected on {device}")
                    return bench
                else:
                    print("no response / invalid")
                    bench.disconnect()
            except Exception as e:
                print(f"error ({e})")
                bench.disconnect()
        
        print("-" * 60)
        print("No AES FPGA accelerator found on any port.")
        return None


def run_nist_test_vector(bench: AESBenchmark) -> bool:
    """Run NIST FIPS-197 Appendix B test vector."""
    print("\n" + "="*60)
    print("NIST FIPS-197 Test Vector")
    print("="*60)
    
    key = bench.NIST_KEY
    plaintext = bench.NIST_PT
    expected_ct = bench.NIST_CT
    
    print(f"Key:       {key.hex()}")
    print(f"Plaintext: {plaintext.hex()}")
    print(f"Expected:  {expected_ct.hex()}")
    
    ciphertext, cycles = bench.encrypt_block(key, plaintext)
    
    if ciphertext is None:
        print("ERROR: No response from FPGA")
        return False
    
    print(f"Got:       {ciphertext.hex()}")
    print(f"Cycles:    {cycles}")
    
    if ciphertext == expected_ct:
        print("RESULT: PASS")
        return True
    else:
        print("RESULT: FAIL")
        return False


def run_random_tests(bench: AESBenchmark, num_tests: int = 100) -> dict:
    """Run random test vectors and collect statistics."""
    print("\n" + "="*60)
    print(f"Random Test Vectors ({num_tests} iterations)")
    print("="*60)
    
    passed = 0
    failed = 0
    cycle_counts = []
    
    for i in range(num_tests):
        # Generate random key and plaintext
        key = os.urandom(16)
        plaintext = os.urandom(16)
        
        # Get hardware result
        hw_ciphertext, cycles = bench.encrypt_block(key, plaintext)
        
        if hw_ciphertext is None:
            print(f"Test {i+1}: ERROR - No response")
            failed += 1
            continue
        
        # Verify against software
        if bench.verify_with_software(key, plaintext, hw_ciphertext):
            passed += 1
            cycle_counts.append(cycles)
            if (i + 1) % 10 == 0:
                print(f"Test {i+1}: PASS ({cycles} cycles)")
        else:
            failed += 1
            print(f"Test {i+1}: FAIL")
            print(f"  Key: {key.hex()}")
            print(f"  PT:  {plaintext.hex()}")
            print(f"  HW:  {hw_ciphertext.hex()}")
            cipher = AES.new(key, AES.MODE_ECB)
            expected = cipher.encrypt(plaintext)
            print(f"  SW:  {expected.hex()}")
    
    stats = {
        'passed': passed,
        'failed': failed,
        'total': num_tests,
        'pass_rate': passed / num_tests * 100 if num_tests > 0 else 0
    }
    
    if cycle_counts:
        stats['min_cycles'] = min(cycle_counts)
        stats['max_cycles'] = max(cycle_counts)
        stats['avg_cycles'] = sum(cycle_counts) / len(cycle_counts)
    
    return stats


def run_throughput_test(bench: AESBenchmark, duration_sec: float = 5.0) -> dict:
    """Measure encryption throughput over a fixed duration."""
    print("\n" + "="*60)
    print(f"Throughput Test ({duration_sec}s duration)")
    print("="*60)
    
    key = os.urandom(16)
    
    start_time = time.time()
    blocks_encrypted = 0
    total_cycles = 0
    
    while (time.time() - start_time) < duration_sec:
        plaintext = os.urandom(16)
        ciphertext, cycles = bench.encrypt_block(key, plaintext)
        
        if ciphertext is not None:
            blocks_encrypted += 1
            total_cycles += cycles
    
    elapsed = time.time() - start_time
    
    stats = {
        'blocks': blocks_encrypted,
        'elapsed_sec': elapsed,
        'blocks_per_sec': blocks_encrypted / elapsed,
        'bytes_per_sec': (blocks_encrypted * 16) / elapsed,
        'kbps': (blocks_encrypted * 16 * 8) / elapsed / 1000,
        'avg_cycles': total_cycles / blocks_encrypted if blocks_encrypted > 0 else 0
    }
    
    return stats


def run_latency_test(bench: AESBenchmark, num_samples: int = 1000) -> dict:
    """Measure round-trip latency (including UART overhead)."""
    print("\n" + "="*60)
    print(f"Latency Test ({num_samples} samples)")
    print("="*60)
    
    key = os.urandom(16)
    latencies = []
    hw_cycles = []
    
    for _ in range(num_samples):
        plaintext = os.urandom(16)
        
        start = time.perf_counter()
        ciphertext, cycles = bench.encrypt_block(key, plaintext)
        end = time.perf_counter()
        
        if ciphertext is not None:
            latencies.append((end - start) * 1000)
            hw_cycles.append(cycles)
    
    if not latencies:
        return {'error': 'No successful measurements'}
    
    latencies.sort()
    hw_cycles.sort()
    
    stats = {
        'samples': len(latencies),
        'min_latency_ms': min(latencies),
        'max_latency_ms': max(latencies),
        'avg_latency_ms': sum(latencies) / len(latencies),
        'median_latency_ms': latencies[len(latencies) // 2],
        'p95_latency_ms': latencies[int(len(latencies) * 0.95)],
        'p99_latency_ms': latencies[int(len(latencies) * 0.99)],
        'min_hw_cycles': min(hw_cycles),
        'max_hw_cycles': max(hw_cycles),
        'avg_hw_cycles': sum(hw_cycles) / len(hw_cycles),
    }
    
    return stats


def run_image_test(bench: AESBenchmark, image_path: str, clock_mhz: float = 125.0) -> bool:
    """
    Encrypt an image using both hardware and software AES-128 ECB mode.
    Compares results and saves encrypted images.
    
    Note: ECB mode is used for demonstration - it's NOT secure for real use
    as it reveals patterns in the image.
    """
    if not HAS_PIL:
        print("ERROR: PIL/Pillow not installed. Run: pip install pillow")
        return False
    
    print("\n" + "="*60)
    print("Image Encryption Test (AES-128 ECB)")
    print("="*60)
    
    if not os.path.exists(image_path):
        print(f"ERROR: Image file not found: {image_path}")
        return False
    
    # Load image
    print(f"Loading image: {image_path}")
    try:
        img = Image.open(image_path)
        # Convert to RGB if necessary
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        width, height = img.size
        print(f"  Size: {width} x {height} pixels")
        print(f"  Mode: {img.mode}")
        
        # Get raw pixel data
        pixels = img.tobytes()
        print(f"  Data size: {len(pixels)} bytes")
    except Exception as e:
        print(f"ERROR: Failed to load image: {e}")
        return False
    
    # Pad to 16-byte boundary
    original_len = len(pixels)
    if len(pixels) % 16 != 0:
        pad_len = 16 - (len(pixels) % 16)
        pixels = pixels + bytes([0] * pad_len)
        print(f"  Padded to: {len(pixels)} bytes (+{pad_len})")
    
    num_blocks = len(pixels) // 16
    print(f"  Blocks: {num_blocks}")
    
    # Generate random key
    key = os.urandom(16)
    print(f"\nEncryption key: {key.hex()}")
    
    # Software encryption (for comparison)
    print("\nSoftware AES-128 ECB encryption...")
    sw_start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_ECB)
    sw_ciphertext = cipher.encrypt(pixels)
    sw_elapsed = time.perf_counter() - sw_start
    print(f"  Time: {sw_elapsed*1000:.2f} ms")
    print(f"  Throughput: {len(pixels) / sw_elapsed / 1e6:.2f} MB/s")
    
    # Hardware encryption
    print("\nHardware AES-128 ECB encryption...")
    hw_ciphertext = bytearray()
    hw_cycles_list = []
    errors = 0
    
    hw_start = time.perf_counter()
    for i in range(num_blocks):
        block = pixels[i*16:(i+1)*16]
        ct, cycles = bench.encrypt_block(key, block)
        
        if ct is None:
            errors += 1
            hw_ciphertext.extend(bytes([0] * 16))  # Placeholder
        else:
            hw_ciphertext.extend(ct)
            hw_cycles_list.append(cycles)
        
        # Progress indicator
        if (i + 1) % 1000 == 0 or i == num_blocks - 1:
            pct = (i + 1) / num_blocks * 100
            print(f"\r  Progress: {i+1}/{num_blocks} blocks ({pct:.1f}%)", end="", flush=True)
    
    hw_elapsed = time.perf_counter() - hw_start
    print()  # Newline after progress
    
    if errors > 0:
        print(f"  Errors: {errors} blocks failed")
    
    print(f"  Total time: {hw_elapsed*1000:.2f} ms")
    print(f"  Throughput: {len(pixels) / hw_elapsed / 1e6:.3f} MB/s")
    
    if hw_cycles_list:
        avg_cycles = sum(hw_cycles_list) / len(hw_cycles_list)
        hw_only_time = avg_cycles * num_blocks / (clock_mhz * 1e6)
        print(f"  Avg HW cycles/block: {avg_cycles:.1f}")
        print(f"  Pure HW time: {hw_only_time*1000:.3f} ms")
        print(f"  Pure HW throughput: {len(pixels) / hw_only_time / 1e6:.1f} MB/s")
        print(f"  UART overhead: {(hw_elapsed - hw_only_time) / hw_elapsed * 100:.1f}%")
    
    # Compare results
    print("\nComparing hardware vs software results...")
    hw_ciphertext = bytes(hw_ciphertext)
    
    if hw_ciphertext == sw_ciphertext:
        print("  MATCH: Hardware and software ciphertexts are identical!")
        match = True
    else:
        # Count differences
        diff_blocks = 0
        for i in range(num_blocks):
            hw_block = hw_ciphertext[i*16:(i+1)*16]
            sw_block = sw_ciphertext[i*16:(i+1)*16]
            if hw_block != sw_block:
                diff_blocks += 1
        print(f"  MISMATCH: {diff_blocks}/{num_blocks} blocks differ")
        match = False
    
    # Save encrypted images
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    output_dir = os.path.dirname(image_path) or "."
    
    def save_encrypted_image(data: bytes, suffix: str):
        """Save encrypted data as image (for visual comparison)."""
        # Truncate back to original length
        data = data[:original_len]
        try:
            enc_img = Image.frombytes('RGB', (width, height), data)
            output_path = os.path.join(output_dir, f"{base_name}_{suffix}.png")
            enc_img.save(output_path)
            print(f"  Saved: {output_path}")
            return output_path
        except Exception as e:
            print(f"  Failed to save {suffix}: {e}")
            return None
    
    print("\nSaving encrypted images...")
    save_encrypted_image(hw_ciphertext, "hw_encrypted")
    save_encrypted_image(sw_ciphertext, "sw_encrypted")
    
    # Also decrypt with software to verify round-trip
    print("\nVerifying decryption (software)...")
    decrypted = cipher.decrypt(hw_ciphertext)
    decrypted = decrypted[:original_len]
    
    if decrypted == pixels[:original_len]:
        print("  Decryption verified: Original data recovered!")
        dec_img = Image.frombytes('RGB', (width, height), decrypted)
        dec_path = os.path.join(output_dir, f"{base_name}_decrypted.png")
        dec_img.save(dec_path)
        print(f"  Saved: {dec_path}")
    else:
        print("  Decryption failed: Data mismatch!")
        match = False
    
    return match


def print_stats(stats: dict, title: str):
    """Pretty-print statistics."""
    print(f"\n{title}:")
    print("-" * 40)
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.3f}")
        else:
            print(f"  {key}: {value}")


def main():
    default_port = get_default_port()
    
    parser = argparse.ArgumentParser(
        description='AES-128 FPGA Benchmark',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Auto-detect:  python aes_benchmark.py --auto
  Windows:      python aes_benchmark.py --port COM3
  Linux:        python aes_benchmark.py --port /dev/ttyUSB1
  
  Image test:   python aes_benchmark.py --auto --image photo.png
  List ports:   python aes_benchmark.py --list-ports
'''
    )
    parser.add_argument('--port', type=str, default=None,
                        help=f'Serial port (default: auto-detect or {default_port})')
    parser.add_argument('--auto', action='store_true',
                        help='Auto-detect FPGA by scanning all ports')
    parser.add_argument('--baud', type=int, default=115200,
                        help='Baud rate (default: 115200)')
    parser.add_argument('--list-ports', action='store_true',
                        help='List available serial ports and exit')
    parser.add_argument('--random-tests', type=int, default=100,
                        help='Number of random test vectors (default: 100)')
    parser.add_argument('--throughput-time', type=float, default=5.0,
                        help='Throughput test duration in seconds (default: 5.0)')
    parser.add_argument('--latency-samples', type=int, default=1000,
                        help='Number of latency test samples (default: 1000)')
    parser.add_argument('--skip-nist', action='store_true',
                        help='Skip NIST test vector')
    parser.add_argument('--skip-random', action='store_true',
                        help='Skip random tests')
    parser.add_argument('--skip-throughput', action='store_true',
                        help='Skip throughput test')
    parser.add_argument('--skip-latency', action='store_true',
                        help='Skip latency test')
    parser.add_argument('--clock-mhz', type=float, default=125.0,
                        help='FPGA clock frequency in MHz (default: 125.0)')
    parser.add_argument('--image', type=str, default=None,
                        help='Path to image file for encryption test')
    
    args = parser.parse_args()
    
    # Handle --list-ports
    if args.list_ports:
        print_available_ports()
        return 0
    
    print("="*60)
    print("AES-128 FPGA Accelerator Benchmark")
    print("="*60)
    print(f"OS:    {platform.system()}")
    print(f"Clock: {args.clock_mhz} MHz")
    
    # Connect to FPGA
    bench = None
    
    if args.auto or args.port is None:
        # Auto-detect
        print("\nAuto-detecting FPGA...")
        bench = AESBenchmark.auto_detect(args.baud)
        if bench is None:
            return 1
    else:
        # Use specified port
        print(f"Port:  {args.port}")
        bench = AESBenchmark(args.port, args.baud)
        if not bench.connect():
            print(f"\nFailed to connect to {args.port}")
            print_available_ports()
            return 1
    
    print(f"\nConnected to: {bench.port}")
    
    try:
        all_passed = True
        
        # Run NIST test vector
        if not args.skip_nist:
            if not run_nist_test_vector(bench):
                all_passed = False
        
        # Run random tests
        if not args.skip_random:
            stats = run_random_tests(bench, args.random_tests)
            print_stats(stats, "Random Test Results")
            if stats['failed'] > 0:
                all_passed = False
        
        # Run throughput test
        if not args.skip_throughput:
            stats = run_throughput_test(bench, args.throughput_time)
            print_stats(stats, "Throughput Results")
            
            if 'avg_cycles' in stats and stats['avg_cycles'] > 0:
                time_per_block_us = stats['avg_cycles'] / args.clock_mhz
                print(f"\nHardware timing (at {args.clock_mhz} MHz):")
                print(f"  Time per block: {time_per_block_us:.3f} us")
                print(f"  Theoretical throughput: {16 / (time_per_block_us / 1e6) / 1e6:.3f} MB/s")
        
        # Run latency test
        if not args.skip_latency:
            stats = run_latency_test(bench, args.latency_samples)
            print_stats(stats, "Latency Results")
            
            if 'avg_latency_ms' in stats and 'avg_hw_cycles' in stats:
                hw_time_ms = stats['avg_hw_cycles'] / (args.clock_mhz * 1000)
                uart_overhead = stats['avg_latency_ms'] - hw_time_ms
                print(f"\nOverhead analysis:")
                print(f"  HW execution time: {hw_time_ms:.6f} ms")
                print(f"  UART overhead: {uart_overhead:.3f} ms")
                print(f"  Overhead %: {uart_overhead / stats['avg_latency_ms'] * 100:.1f}%")
        
        # Run image encryption test
        if args.image:
            if not run_image_test(bench, args.image, args.clock_mhz):
                all_passed = False
        
        # Final summary
        print("\n" + "="*60)
        if all_passed:
            print("ALL TESTS PASSED")
        else:
            print("SOME TESTS FAILED")
        print("="*60)
        
        return 0 if all_passed else 1
        
    finally:
        bench.disconnect()


if __name__ == '__main__':
    sys.exit(main())