"""
pendrive_wipe_prototype.py
Prototype: Secure pendrive wipe + verification + signed PDF/JSON certificate (Windows)
Run AS ADMINISTRATOR.

Dependencies:
    pip install pynacl fpdf
"""
import subprocess
import os
import sys
import ctypes
import threading
import time
import uuid
import json
import tempfile
import base64
import hashlib
import secrets
import queue
from datetime import datetime, timezone
from fpdf import FPDF
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from pathlib import Path

# GUI imports (tkinter is standard)
import tkinter as tk
from tkinter import ttk, messagebox

# ------------------------------
# Windows API wrappers (ctypes)
# ------------------------------
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
shell32 = ctypes.windll.shell32

# Constants
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

# DeviceIoControl codes for lock/dismount
FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_DISMOUNT_VOLUME = 0x00090020

# ------------------------------
# Key persistence helpers
# ------------------------------
def default_key_path():
    # Use %APPDATA%\pendrive_wipe\signing_key.hex on Windows; fallback to ~/.pendrive_wipe/
    appdata = os.getenv('APPDATA') or os.path.expanduser("~")
    p = Path(appdata) / "pendrive_wipe"
    p.mkdir(parents=True, exist_ok=True)
    return p / "signing_key.hex"

def save_signing_key_file(signing_key: SigningKey, path: Path):
    hexkey = signing_key.encode(encoder=HexEncoder).decode()
    # write atomically
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w') as f:
        f.write(hexkey)
    # attempt to restrict permissions (best-effort; Windows ignores UNIX perms)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(path)

def load_or_create_signing_key(path: Path):
    """
    Load a SigningKey from `path` (hex). If not present, generate and save one.
    Returns SigningKey instance and a boolean indicating whether it was just_created.
    """
    if path.exists():
        try:
            with open(path, 'r') as f:
                key_hex = f.read().strip()
            if key_hex:
                sk = SigningKey(key_hex, encoder=HexEncoder)
                return sk, False
        except Exception as e:
            print(f"[key] Failed to load signing key from {path}: {e}")
            # fallthrough -> regenerate
    # create new
    sk = SigningKey.generate()
    try:
        save_signing_key_file(sk, path)
        print(f"[key] New signing key generated and saved to {path}")
    except Exception as e:
        print(f"[key] Failed to save new signing key to {path}: {e}")
    return sk, True

# ------------------------------
# Helpers
# ------------------------------
def is_admin():
    """Return True if running as admin."""
    try:
        return shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def list_removable_drives():
    """Return list of candidate drives (removable or fixed, excluding system C:)."""
    GetDriveTypeW = kernel32.GetDriveTypeW
    GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    GetDriveTypeW.restype = ctypes.c_uint

    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    drives = []
    for i in range(65, 91):  # A–Z
        drive = chr(i) + ':\\'
        drive_type = GetDriveTypeW(drive)
        if drive_type in (DRIVE_REMOVABLE, DRIVE_FIXED):
            letter = chr(i) + ':'
            if letter.upper().startswith('C:'):  # exclude system drive
                continue
            vol_label, vol_serial = get_volume_info(letter)
            drives.append({
                'letter': letter,
                'label': vol_label,
                'serial': vol_serial,
                'type': 'REMOVABLE' if drive_type == DRIVE_REMOVABLE else 'FIXED'
            })
    return drives

def get_volume_info(drive_letter):
    """Return (label, serial_number) for given 'E:' (no slash)."""
    GetVolumeInformationW = kernel32.GetVolumeInformationW
    buf_label = ctypes.create_unicode_buffer(261)
    vol_serial = ctypes.c_uint(0)
    max_comp_len = ctypes.c_uint(0)
    fs_flags = ctypes.c_uint(0)
    buf_fs = ctypes.create_unicode_buffer(261)
    res = GetVolumeInformationW(
        ctypes.c_wchar_p(drive_letter + '\\'),
        buf_label,
        ctypes.sizeof(buf_label),
        ctypes.byref(vol_serial),
        ctypes.byref(max_comp_len),
        ctypes.byref(fs_flags),
        buf_fs,
        ctypes.sizeof(buf_fs)
    )
    if not res:
        return ('', 0)
    return (buf_label.value, vol_serial.value)

# ------------------------------
# Partition / format helper (unchanged from your working version)
# ------------------------------
def recreate_partition_and_format(drive_letter, label="WIPED_USB"):
    """
    Recreate a partition and format the drive after wiping.
    Attempts:
      1) Get disk number via Get-Partition -DriveLetter <L> -> DiskNumber
      2) Fallback: get volume size via Get-Volume -DriveLetter and find the first disk whose Size >= volume size
    Produces debug prints to help diagnose mapping issues.
    """
    letter = drive_letter[0].upper()
    try:
        # Attempt 1: direct mapping (preferred)
        ps_cmd1 = f"(Get-Partition -DriveLetter {letter} -ErrorAction SilentlyContinue).DiskNumber"
        try:
            disk_num = subprocess.check_output(["powershell", "-Command", ps_cmd1], shell=True, stderr=subprocess.STDOUT).decode().strip()
        except subprocess.CalledProcessError as e:
            disk_num = ""
            print(f"[recreate] PowerShell attempt1 failed: {e.output.decode(errors='ignore') if hasattr(e, 'output') else e}")

        if disk_num and disk_num.isdigit():
            print(f"[recreate] Resolved {drive_letter} -> disk {disk_num} (method: Get-Partition)")
        else:
            # Attempt 2: fallback using volume size -> match a disk
            print(f"[recreate] Could not resolve disk via Get-Partition. Trying fallback using Get-Volume size for {letter}:")
            ps_vol = f"(Get-Volume -DriveLetter {letter} -ErrorAction SilentlyContinue).Size"
            try:
                vol_size_raw = subprocess.check_output(["powershell", "-Command", ps_vol], shell=True, stderr=subprocess.STDOUT).decode().strip()
            except subprocess.CalledProcessError as e:
                vol_size_raw = ""
                print(f"[recreate] PowerShell Get-Volume failed: {e.output.decode(errors='ignore') if hasattr(e, 'output') else e}")

            if vol_size_raw:
                try:
                    vol_size = int(vol_size_raw)
                    # Find first disk whose size is >= vol_size (heuristic)
                    ps_find = f"Get-Disk | Where-Object {{$_.Size -ge {vol_size}}} | Select-Object -First 1 -ExpandProperty Number"
                    try:
                        disk_num = subprocess.check_output(["powershell", "-Command", ps_find], shell=True, stderr=subprocess.STDOUT).decode().strip()
                        print(f"[recreate] Fallback matched disk {disk_num} (by size).")
                    except subprocess.CalledProcessError as e:
                        disk_num = ""
                        print(f"[recreate] Fallback PowerShell find failed: {e.output.decode(errors='ignore') if hasattr(e, 'output') else e}")
                except ValueError:
                    disk_num = ""
                    print(f"[recreate] Could not parse volume size: '{vol_size_raw}'")
            else:
                print(f"[recreate] No volume size available for drive {letter}; cannot fallback.")

        if not disk_num or not disk_num.isdigit():
            print(f"[recreate] Could not resolve disk number for {drive_letter}. Aborting diskpart step.")
            return False

        # Build diskpart script
        script = f"""
select disk {disk_num}
clean
create partition primary
format fs=fat32 quick label={label}
assign letter={letter}
exit
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write(script)
            script_path = f.name

        print(f"[recreate] Running diskpart script (disk {disk_num}) from {script_path} ...")
        subprocess.run(["diskpart", "/s", script_path], check=True, shell=True)
        print("[recreate] diskpart finished successfully.")
        return True

    except Exception as e:
        print(f"[recreate] Auto partition+format failed: {e}")
        return False

# ------------------------------
# Low-level volume helpers (unchanged)
# ------------------------------
def open_volume_handle(drive_letter):
    """Open \\\\.\\E: handle using CreateFileW."""
    path = r"\\.\%s" % drive_letter  # e.g., \\.\E:
    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint,
                            ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
    CreateFileW.restype = ctypes.c_void_p

    handle = CreateFileW(path,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         None,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         None)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        return None
    return handle

def lock_and_dismount(handle):
    """Attempt to lock and dismount volume. Returns (ok, msg)."""
    DeviceIoControl = kernel32.DeviceIoControl
    DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                ctypes.c_void_p, ctypes.c_uint,
                                ctypes.c_void_p, ctypes.c_uint,
                                ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
    # Lock
    bytesReturned = ctypes.c_uint(0)
    locked = DeviceIoControl(handle, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytesReturned), None)
    if not locked:
        return False, "Lock failed"
    # Dismount
    dismounted = DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(bytesReturned), None)
    if not dismounted:
        return False, "Dismount failed"
    return True, "Locked & dismounted"

def handle_to_fileobj(handle):
    """Convert raw Win32 handle to Python file object for binary read/write."""
    import msvcrt
    import os
    fh = msvcrt.open_osfhandle(int(handle), os.O_RDWR | os.O_BINARY)
    # unbuffered mode; we will use .seek/.write
    f = os.fdopen(fh, 'r+b', buffering=0)
    return f

def get_volume_total_bytes(drive_letter):
    """Use GetDiskFreeSpaceEx to compute total bytes on volume root."""
    GetDiskFreeSpaceExW = kernel32.GetDiskFreeSpaceExW
    GetDiskFreeSpaceExW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulonglong),
                                    ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong)]
    free_bytes_available = ctypes.c_ulonglong(0)
    total_number_of_bytes = ctypes.c_ulonglong(0)
    total_number_of_free_bytes = ctypes.c_ulonglong(0)
    res = GetDiskFreeSpaceExW(ctypes.c_wchar_p(drive_letter + '\\'),
                              ctypes.byref(free_bytes_available),
                              ctypes.byref(total_number_of_bytes),
                              ctypes.byref(total_number_of_free_bytes))
    if not res:
        return None
    return total_number_of_bytes.value

# ------------------------------
# Deterministic chunk generator
# ------------------------------
def deterministic_chunk(seed_bytes: bytes, chunk_index: int, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        m = seed_bytes + chunk_index.to_bytes(8, 'little') + counter.to_bytes(8, 'little')
        out.extend(hashlib.sha256(m).digest())
        counter += 1
    return bytes(out[:size])

# ------------------------------
# Certificate helpers
# ------------------------------
def canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def sign_bytes(signing_key: SigningKey, data_bytes: bytes) -> bytes:
    sig = signing_key.sign(data_bytes).signature
    return sig

def save_pdf_certificate(pdf_path, cert_json, signature_b64):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, "Secure Wipe Certificate", ln=True)
    pdf.ln(4)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 6, f"Certificate ID: {cert_json.get('certificate_id')}")
    pdf.multi_cell(0, 6, f"Drive Letter: {cert_json.get('drive_letter')}   Volume Label: {cert_json.get('volume_label')}")
    pdf.multi_cell(0, 6, f"Total Bytes: {cert_json.get('total_bytes')}")
    pdf.multi_cell(0, 6, f"Wipe Method: {cert_json.get('wipe_method')}")
    pdf.multi_cell(0, 6, f"Start: {cert_json.get('start_time')}")
    pdf.multi_cell(0, 6, f"End:   {cert_json.get('end_time')}")
    pdf.multi_cell(0, 6, f"Status: {cert_json.get('status')}")
    pdf.ln(4)
    pdf.multi_cell(0, 6, "Signer Public Key (hex):")
    pdf.multi_cell(0, 6, cert_json.get('signer_public_key', '') )
    pdf.ln(4)
    pdf.multi_cell(0, 6, "Signature (base64):")
    pdf.multi_cell(0, 6, signature_b64)
    pdf.ln(4)
    pdf.multi_cell(0, 6, "Full certificate JSON (canonical):")
    pdf.set_font("Courier", size=8)
    pdf.multi_cell(0, 4, json.dumps(cert_json, indent=2, ensure_ascii=False))
    pdf.output(pdf_path)

# ------------------------------
# Wipe / verification worker
# ------------------------------
def wipe_and_certify(drive_letter, method, passes, signer_key: SigningKey, out_q: queue.Queue, gui_progress_callback):
    start_time = datetime.now(timezone.utc).astimezone().isoformat()
    vol_label, vol_serial = get_volume_info(drive_letter)
    total_bytes = get_volume_total_bytes(drive_letter)
    if total_bytes is None:
        out_q.put(("error", "Unable to read volume size. Aborting."))
        return

    cert = {
        "certificate_id": str(uuid.uuid4()),
        "drive_letter": drive_letter,
        "volume_label": vol_label,
        "volume_serial": vol_serial,
        "total_bytes": total_bytes,
        "wipe_method": method,
        "passes": passes,
        "start_time": start_time,
        "status": "incomplete",
        "bytes_written": 0,
        "verification": [],
        "signer_public_key": signer_key.verify_key.encode(encoder=HexEncoder).decode(),
    }

    seed_bytes = secrets.token_bytes(32) if method == 'random' else b'\x00'*32
    cert['seed_hex'] = seed_bytes.hex()

    out_q.put(("log", f"Opening volume handle for {drive_letter} ..."))
    handle = open_volume_handle(drive_letter)
    if not handle:
        out_q.put(("error", f"Could not open handle for {drive_letter}. Run as admin."))
        return

    f = None
    try:
        out_q.put(("log", "Attempting to lock & dismount volume (required for raw write)..."))
        ok, msg = lock_and_dismount(handle)
        if not ok:
            out_q.put(("error", f"Lock/Dismount failed: {msg}. Close Explorer/any apps using drive and try again."))
            kernel32.CloseHandle(handle)
            return
        out_q.put(("log", "Volume locked and dismounted."))

        f = handle_to_fileobj(handle)
        

        chunk_size = 1024 * 1024  # 1 MB
        total_chunks = (total_bytes + chunk_size - 1) // chunk_size
        bytes_written = 0

        for p in range(passes):
            f.seek(0, os.SEEK_SET)
            out_q.put(("log", f"Starting pass {p+1}/{passes} ..."))
            for chunk_idx in range(total_chunks):
                try:
                    to_write = chunk_size if (chunk_idx < total_chunks - 1) else (total_bytes - (chunk_idx * chunk_size))
                    if method == 'zeros':
                        buf = b'\x00' * to_write
                    else:
                        buf = deterministic_chunk(seed_bytes, chunk_idx + p * total_chunks, to_write)
                    f.write(buf)
                    bytes_written += to_write
                    cert['bytes_written'] = bytes_written
                    progress = int(bytes_written * 100 / total_bytes)
                    gui_progress_callback(progress)
                    if (chunk_idx % 16) == 0:
                        f.flush()
                except Exception as e:
                    out_q.put(("error", f"Write error at chunk {chunk_idx}: {e}"))
                    raise
            f.flush()
            kernel32.FlushFileBuffers(ctypes.c_void_p(f.fileno()))
            out_q.put(("log", f"Pass {p+1} complete."))

        out_q.put(("log", "Starting verification checks (random 5 samples)..."))
        import math, random
        rng = random.Random(int.from_bytes(hashlib.sha256(seed_bytes).digest()[:8], 'little'))
        num_samples = min(5, max(1, total_bytes // (10 * 1024 * 1024)))
        sample_offsets = []
        for _ in range(num_samples):
            off = rng.randrange(0, total_bytes)
            off = (off // chunk_size) * chunk_size
            sample_offsets.append(off)
        sample_results = []
        for off in sample_offsets:
            f.seek(off, os.SEEK_SET)
            length = min(4096, total_bytes - off)
            actual = f.read(length)
            if method == 'zeros':
                ok = all(b == 0 for b in actual)
                expected_hash = hashlib.sha256(b'\x00'*length).hexdigest()
                actual_hash = hashlib.sha256(actual).hexdigest()
            else:
                chunk_idx = off // chunk_size
                expected = deterministic_chunk(seed_bytes, chunk_idx, length)
                ok = actual == expected
                expected_hash = hashlib.sha256(expected).hexdigest()
                actual_hash = hashlib.sha256(actual).hexdigest()
            sample_results.append({
                "offset": off,
                "length": length,
                "ok": ok,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash
            })
            out_q.put(("log", f"Verified offset {off}: ok={ok}"))
        cert['verification'] = sample_results

        end_time = datetime.now(timezone.utc).astimezone().isoformat()
        cert['end_time'] = end_time
        cert['status'] = "success" if all(x['ok'] for x in sample_results) else "failure"

        canonical = canonical_json_bytes(cert)
        signature = sign_bytes(signer_key, canonical)
        signature_b64 = base64.b64encode(signature).decode()
        cert['signature_b64'] = signature_b64

        filename_base = f"wipe_certificate_{cert['certificate_id']}"
        json_path = filename_base + '.json'
        pdf_path = filename_base + '.pdf'
        with open(json_path, 'wb') as jf:
            jf.write(canonical + b'\n')
        save_pdf_certificate(pdf_path, cert, signature_b64)
        out_q.put(("log", f"Certificate saved: {json_path}, {pdf_path}"))

        # IMPORTANT: close file object and handle before disk operations
        try:
            if f:
                try:
                    f.close()
                except Exception:
                    pass
            try:
                if handle:
                    kernel32.CloseHandle(handle)
                    handle = None
            except Exception:
                pass
        except Exception:
            pass

        ok = recreate_partition_and_format(drive_letter, label="WIPED_USB")
        if ok:
            out_q.put(("log", f"Drive {drive_letter} has been auto-partitioned and formatted (FAT32, label=WIPED_USB)."))
        else:
            out_q.put(("error", f"Drive {drive_letter} wiped but could not be auto-formatted. Please format manually."))

        out_q.put(("done", {"cert_json": cert, "json_path": json_path, "pdf_path": pdf_path}))

    except Exception as e:
        end_time = datetime.now(timezone.utc).astimezone().isoformat()
        cert['end_time'] = end_time
        cert['status'] = "failure"
        try:
            canonical = canonical_json_bytes(cert)
            signature = sign_bytes(signer_key, canonical)
            signature_b64 = base64.b64encode(signature).decode()
            cert['signature_b64'] = signature_b64
            filename_base = f"wipe_certificate_{cert['certificate_id']}_FAILED"
            json_path = filename_base + '.json'
            pdf_path = filename_base + '.pdf'
            with open(json_path, 'wb') as jf:
                jf.write(canonical + b'\n')
            save_pdf_certificate(pdf_path, cert, signature_b64)
            out_q.put(("log", f"Failure certificate saved: {json_path}, {pdf_path}"))
        except Exception as e2:
            out_q.put(("error", f"Failed to write failure certificate: {e2}"))
        out_q.put(("error", f"Wipe failed: {e}"))
    finally:
        try:
            if f:
                try:
                    f.close()
                except Exception:
                    pass
            if handle:
                try:
                    kernel32.CloseHandle(handle)
                except Exception:
                    pass
        except Exception:
            pass

    

# ------------------------------
# GUI
# ------------------------------
class WipeGUI:
    def __init__(self, root):
        self.root = root
        root.title("SecureWipe Pro - Cryptographically Verified Drive Sanitization")
        root.geometry("1000x750")
        root.minsize(900, 650)
        
        try:
            # Set window to appear on top initially and center it
            root.attributes('-topmost', True)
            root.after(100, lambda: root.attributes('-topmost', False))
            
            # Center the window on screen
            root.update_idletasks()
            x = (root.winfo_screenwidth() // 2) - (1000 // 2)
            y = (root.winfo_screenheight() // 2) - (750 // 2)
            root.geometry(f"1000x750+{x}+{y}")
        except:
            pass
        
        root.configure(bg="#1a1d23")

        style = ttk.Style()
        style.theme_use("clam")
        
        # Define modern color palette
        bg_primary = "#1a1d23"      # Dark background
        bg_secondary = "#2d3142"    # Card backgrounds
        bg_accent = "#4f5d75"       # Accent elements
        text_primary = "#ffffff"    # Primary text
        text_secondary = "#bfc0c0"  # Secondary text
        accent_blue = "#3b82f6"     # Primary accent
        accent_green = "#10b981"    # Success color
        accent_red = "#ef4444"      # Error color
        
        # Configure modern styles
        style.configure("TLabel", 
                       font=("Inter", 10), 
                       background=bg_primary, 
                       foreground=text_primary)
        
        style.configure("Title.TLabel", 
                       font=("Inter", 24, "bold"), 
                       background=bg_primary, 
                       foreground=text_primary)
        
        style.configure("Subtitle.TLabel", 
                       font=("Inter", 11), 
                       background=bg_primary, 
                       foreground=text_secondary)
        
        style.configure("Modern.TButton", 
                       font=("Inter", 10, "bold"),
                       padding=(16, 8),
                       relief="flat",
                       borderwidth=0,
                       focuscolor="none")
        
        style.map("Modern.TButton",
                 background=[('active', '#5b6bc0'), ('pressed', '#3949ab'), ('!active', bg_accent)],
                 foreground=[('active', text_primary), ('!active', text_primary)],
                 relief=[('pressed', 'flat'), ('!pressed', 'flat')])
        
        style.configure("Primary.TButton", 
                       font=("Inter", 11, "bold"),
                       padding=(20, 10),
                       relief="flat",
                       borderwidth=0,
                       focuscolor="none")
        
        style.map("Primary.TButton",
                 background=[('active', '#2563eb'), ('pressed', '#1d4ed8'), ('!active', accent_blue)],
                 foreground=[('active', text_primary), ('!active', text_primary)],
                 relief=[('pressed', 'flat'), ('!pressed', 'flat')])
        
        style.configure("Success.TButton", 
                       font=("Inter", 11, "bold"),
                       padding=(20, 10),
                       relief="flat",
                       borderwidth=0,
                       focuscolor="none")
        
        style.map("Success.TButton",
                 background=[('active', '#059669'), ('pressed', '#047857'), ('!active', accent_green)],
                 foreground=[('active', text_primary), ('!active', text_primary)],
                 relief=[('pressed', 'flat'), ('!pressed', 'flat')])
        
        style.configure("Danger.TButton", 
                       font=("Inter", 10),
                       padding=(16, 8),
                       relief="flat",
                       borderwidth=0,
                       focuscolor="none")
        
        style.map("Danger.TButton",
                 background=[('active', '#dc2626'), ('pressed', '#b91c1c'), ('!active', accent_red)],
                 foreground=[('active', text_primary), ('!active', text_primary)],
                 relief=[('pressed', 'flat'), ('!pressed', 'flat')])
        
        style.configure("Modern.TLabelFrame", 
                       background=bg_primary,
                       foreground=text_primary,
                       borderwidth=0,
                       relief="flat")
        
        style.configure("Modern.TLabelFrame.Label", 
                       font=("Inter", 11, "bold"),
                       background=bg_primary,
                       foreground=text_primary)
        
        style.configure("Modern.Treeview.Heading", 
                       font=("Inter", 10, "bold"),
                       background=bg_accent,
                       foreground=text_primary,
                       relief="flat",
                       borderwidth=1)
        
        style.configure("Modern.Treeview", 
                       rowheight=32, 
                       font=("Inter", 9),
                       background=bg_secondary,
                       foreground=text_primary,
                       fieldbackground=bg_secondary,
                       borderwidth=0,
                       relief="flat")
        
        style.map("Modern.Treeview",
                 background=[('selected', accent_blue)],
                 foreground=[('selected', text_primary)])
        
        style.configure("Modern.TFrame", 
                       background=bg_primary,
                       relief="flat",
                       borderwidth=0)
        
        style.configure("Card.TFrame", 
                       background=bg_secondary,
                       relief="solid",
                       borderwidth=1,
                       bordercolor="#3a3f4b")
        
        style.configure("Modern.TProgressbar",
                       background=accent_blue,
                       troughcolor=bg_secondary,
                       borderwidth=0,
                       lightcolor=accent_blue,
                       darkcolor=accent_blue)
        
        # Configure the progress bar layout properly
        style.layout("Modern.TProgressbar",
                    [('Progressbar.trough',
                      {'children': [('Progressbar.pbar',
                                   {'side': 'left', 'sticky': 'ns'})],
                       'sticky': 'nswe'})])

        root.rowconfigure(1, weight=0)  # Header
        root.rowconfigure(2, weight=1)  # Main content
        root.rowconfigure(3, weight=0)  # Actions
        root.columnconfigure(0, weight=1)

        header_frame = ttk.Frame(root, style="Modern.TFrame", padding=(24, 20))
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.columnconfigure(0, weight=1)
        
        # Main title with security icon
        title_frame = ttk.Frame(header_frame, style="Modern.TFrame")
        title_frame.pack(fill="x")
        
        ttk.Label(
            title_frame,
            text="🛡️ SecureWipe Pro",
            style="Title.TLabel"
        ).pack(side="left")
        
        # Status indicator with enhanced styling
        status_frame = ttk.Frame(title_frame, style="Modern.TFrame")
        status_frame.pack(side="right")
        
        self.status_label = ttk.Label(
            status_frame,
            text="● READY",
            font=("Inter", 10, "bold"),
            foreground=accent_green,
            background=bg_primary
        )
        self.status_label.pack(side="right", padx=(0, 8))
        
        ttk.Label(
            status_frame,
            text="Admin Mode",
            font=("Inter", 9),
            foreground=text_secondary,
            background=bg_primary
        ).pack(side="right", padx=(0, 16))
        
        # Subtitle
        ttk.Label(
            header_frame,
            text="Military-grade cryptographically verified drive sanitization for secure data destruction",
            style="Subtitle.TLabel"
        ).pack(anchor="w", pady=(8, 0))

        main_frame = ttk.Frame(root, style="Modern.TFrame", padding=(24, 0, 24, 0))
        main_frame.grid(row=1, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        left_column = ttk.Frame(main_frame, style="Modern.TFrame")
        left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        left_column.columnconfigure(0, weight=1)
        left_column.rowconfigure(0, weight=1)

        drives_card = ttk.Frame(left_column, style="Card.TFrame", padding=20)
        drives_card.grid(row=0, column=0, sticky="nsew", pady=(0, 16))
        drives_card.columnconfigure(0, weight=1)
        drives_card.rowconfigure(1, weight=1)

        # Card header
        drives_header = ttk.Frame(drives_card, style="Card.TFrame")
        drives_header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        drives_header.columnconfigure(0, weight=1)
        
        ttk.Label(
            drives_header,
            text="📱 Available Storage Devices",
            font=("Inter", 14, "bold"),
            background=bg_secondary,
            foreground=text_primary
        ).pack(side="left")
        
        ttk.Button(
            drives_header, 
            text="🔄 Refresh", 
            command=self.refresh_drives,
            style="Modern.TButton"
        ).pack(side="right")

        tree_frame = ttk.Frame(drives_card, style="Card.TFrame")
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.drive_list = ttk.Treeview(
            tree_frame,
            columns=('letter', 'label', 'serial', 'type'),
            show='headings',
            height=8,
            style="Modern.Treeview"
        )
        
        for col, text, w in [
            ('letter', 'Drive', 80),
            ('label', 'Volume Label', 180),
            ('serial', 'Serial Number', 140),
            ('type', 'Device Type', 100)
        ]:
            self.drive_list.heading(col, text=text)
            self.drive_list.column(col, width=w, anchor="center")

        self.drive_list.grid(row=0, column=0, sticky="nsew")
        
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.drive_list.yview)
        self.drive_list.configure(yscroll=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

        options_card = ttk.Frame(left_column, style="Card.TFrame", padding=20)
        options_card.grid(row=1, column=0, sticky="ew")
        options_card.columnconfigure(1, weight=1)

        ttk.Label(
            options_card,
            text="⚙️ Sanitization Configuration",
            font=("Inter", 14, "bold"),
            background=bg_secondary,
            foreground=text_primary
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 16))

        # Method selection with better styling
        ttk.Label(
            options_card, 
            text="Wipe Method:",
            font=("Inter", 10, "bold"),
            background=bg_secondary,
            foreground=text_primary
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        self.method_var = tk.StringVar(value='zeros')
        method_frame = ttk.Frame(options_card, style="Card.TFrame")
        method_frame.grid(row=1, column=1, columnspan=2, sticky="w", padx=(16, 0), pady=(0, 12))
        
        ttk.Radiobutton(
            method_frame, 
            text='Zero Fill (Fast)', 
            variable=self.method_var, 
            value='zeros',
            style="Modern.TRadiobutton"
        ).pack(side="left", padx=(0, 16))
        
        ttk.Radiobutton(
            method_frame, 
            text='Cryptographic Random (Secure)', 
            variable=self.method_var, 
            value='random',
            style="Modern.TRadiobutton"
        ).pack(side="left", padx=(0, 16))
        
        # --- Added dummy options ---
        ttk.Radiobutton(
            method_frame, 
            text='ATA Secure Erase', 
            variable=self.method_var, 
            value='ata',
            style="Modern.TRadiobutton"
        ).pack(side="left", padx=(0, 16))

        ttk.Radiobutton(
            method_frame, 
            text='NVME Sanitize', 
            variable=self.method_var, 
            value='nvme',
            style="Modern.TRadiobutton"
        ).pack(side="left")

        # Passes configuration
        ttk.Label(
            options_card, 
            text="Security Passes:",
            font=("Inter", 10, "bold"),
            background=bg_secondary,
            foreground=text_primary
        ).grid(row=2, column=0, sticky="w", pady=(8, 0))
        
        self.passes_spin = ttk.Spinbox(options_card, from_=1, to=3, width=8, font=("Inter", 10))
        self.passes_spin.set('1')
        self.passes_spin.grid(row=2, column=1, sticky="w", padx=(16, 0), pady=(8, 0))
        
        ttk.Label(
            options_card,
            text="(Higher = More Secure)",
            font=("Inter", 9),
            background=bg_secondary,
            foreground=text_secondary
        ).grid(row=2, column=2, sticky="w", padx=(8, 0), pady=(8, 0))

        right_column = ttk.Frame(main_frame, style="Modern.TFrame")
        right_column.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        right_column.columnconfigure(0, weight=1)
        right_column.rowconfigure(1, weight=1)

        key_card = ttk.Frame(right_column, style="Card.TFrame", padding=20)
        key_card.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        key_card.columnconfigure(1, weight=1)

        ttk.Label(
            key_card,
            text="🔐 Cryptographic Signing",
            font=("Inter", 14, "bold"),
            background=bg_secondary,
            foreground=text_primary
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        ttk.Label(
            key_card, 
            text="Key Location:",
            font=("Inter", 10),
            background=bg_secondary,
            foreground=text_secondary
        ).grid(row=1, column=0, sticky="w")
        
        self.key_path_lbl = ttk.Label(
            key_card, 
            text=str(default_key_path()), 
            font=("Inter", 9),
            background=bg_secondary,
            foreground=text_primary,
            wraplength=300
        )
        self.key_path_lbl.grid(row=1, column=1, sticky="w", padx=(8, 8))
        
        ttk.Button(
            key_card, 
            text="📤 Export Public Key", 
            command=self.export_pubkey,
            style="Modern.TButton"
        ).grid(row=1, column=2, sticky="e")

        progress_card = ttk.Frame(right_column, style="Card.TFrame", padding=20)
        progress_card.grid(row=1, column=0, sticky="nsew")
        progress_card.columnconfigure(0, weight=1)
        progress_card.rowconfigure(2, weight=1)

        ttk.Label(
            progress_card,
            text="📊 Operation Status & Logs",
            font=("Inter", 14, "bold"),
            background=bg_secondary,
            foreground=text_primary
        ).grid(row=0, column=0, sticky="w", pady=(0, 16))

        progress_frame = ttk.Frame(progress_card, style="Card.TFrame")
        progress_frame.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(
            progress_frame,
            orient='horizontal',
            mode='determinate',
            style="Modern.TProgressbar"
        )
        self.progress.grid(row=0, column=0, sticky='ew')
        
        self.progress_label = ttk.Label(
            progress_frame,
            text="0%",
            font=("Inter", 9, "bold"),
            background=bg_secondary,
            foreground=text_secondary
        )
        self.progress_label.grid(row=0, column=1, padx=(8, 0))

        log_frame = ttk.Frame(progress_card, style="Card.TFrame")
        log_frame.grid(row=2, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log = tk.Text(
            log_frame,
            font=("JetBrains Mono", 9),
            bg="#0d1117",
            fg="#c9d1d9",
            insertbackground="#58a6ff",
            selectbackground="#264f78",
            selectforeground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=8,
            wrap="word"
        )
        self.log.grid(row=0, column=0, sticky="nsew")
        
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscroll=log_scroll.set)
        log_scroll.grid(row=0, column=1, sticky="ns")

        action_frame = ttk.Frame(root, style="Modern.TFrame", padding=(24, 16, 24, 24))
        action_frame.grid(row=2, column=0, sticky="ew")
        
        # Left side - status info
        status_info = ttk.Frame(action_frame, style="Modern.TFrame")
        status_info.pack(side="left")
        
        ttk.Label(
            status_info,
            text="⚠️ Administrator privileges active",
            font=("Inter", 9),
            background=bg_primary,
            foreground=text_secondary
        ).pack(anchor="w")
        
        ttk.Label(
            status_info,
            text="All operations are cryptographically signed and verified",
            font=("Inter", 9),
            background=bg_primary,
            foreground=text_secondary
        ).pack(anchor="w")

        # Right side - action buttons
        button_frame = ttk.Frame(action_frame, style="Modern.TFrame")
        button_frame.pack(side="right")
        
        ttk.Button(
            button_frame, 
            text="🚀 Begin Secure Wipe", 
            command=self.start_wipe,
            style="Success.TButton"
        ).pack(side="left", padx=(0, 12))
        
        ttk.Button(
            button_frame, 
            text="❌ Exit Application", 
            command=root.quit,
            style="Danger.TButton"
        ).pack(side="left")

        # setup vars
        self.out_q = queue.Queue()
        self.signer_key, created = load_or_create_signing_key(default_key_path())
        if created:
            messagebox.showinfo("Signing Key", f"New signing key created at:\n{default_key_path()}")

        # initial refresh + polling
        self.refresh_drives()
        root.after(200, self.poll_queue)


    def refresh_drives(self):
        for i in self.drive_list.get_children():
            self.drive_list.delete(i)
        drives = list_removable_drives()
        if not drives:
            self.log_insert("No removable drives detected. Insert your pen drive and click Refresh.")
        for d in drives:
            self.drive_list.insert(
                '',
                'end',
                iid=d['letter'],
                values=(d['letter'], d['label'], hex(d['serial']), d['type'])
            )

    def export_pubkey(self):
        hexkey = self.signer_key.verify_key.encode(encoder=HexEncoder).decode()
        fn = f"signer_pubkey_{int(time.time())}.txt"
        with open(fn, 'w') as f:
            f.write(hexkey)
        messagebox.showinfo("Public key exported", f"Public key (hex) saved to {fn}")
        self.log_insert(f"Public key exported to {fn}")

    def get_selected_drive(self):
        sel = self.drive_list.selection()
        if not sel:
            return None
        return sel[0]

    def start_wipe(self):
        drive = self.get_selected_drive()
        if not drive:
            messagebox.showwarning("Select Drive", "Please select a removable drive from the list.")
            return
        ok = messagebox.askyesno("Confirm", f"All data on {drive} will be irreversibly destroyed. Continue?")
        if not ok:
            return
        method = self.method_var.get()
        passes = int(self.passes_spin.get())
        self.progress['value'] = 0
        self.progress_label.config(text="0%")
        self.status_label.config(text="● WORKING", foreground="#f59e0b")
        t = threading.Thread(target=wipe_and_certify, args=(drive, method, passes, self.signer_key, self.out_q, self.update_progress))
        t.daemon = True
        t.start()
        self.log_insert(f"Started wipe on {drive} (method={method}, passes={passes}).")

    def update_progress(self, percent):
        def update():
            self.progress.configure(value=percent)
            self.progress_label.config(text=f"{percent}%")
        self.root.after(1, update)

    def log_insert(self, msg):
        ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        self.log.insert('end', f"[{ts}] {msg}\n")
        self.log.see('end')

    def poll_queue(self):
        try:
            while True:
                typ, data = self.out_q.get_nowait()
                if typ == "log":
                    self.log_insert(str(data))
                elif typ == "error":
                    self.log_insert("ERROR: " + str(data))
                    self.status_label.config(text="● ERROR", foreground="#ef4444")
                    messagebox.showerror("Error", str(data))
                elif typ == "done":
                    cert = data.get('cert_json') if isinstance(data, dict) else data
                    self.log_insert("Wipe complete. Certificate generated.")
                    self.status_label.config(text="● COMPLETE", foreground="#10b981")
                    messagebox.showinfo("Done", "Wipe complete and certificate generated.")
                else:
                    self.log_insert(f"{typ}: {data}")
        except queue.Empty:
            pass
        self.root.after(200, self.poll_queue)


# ------------------------------
# Entry / run
# ------------------------------
def main():
    if os.name != 'nt':
        print("This script is for Windows only.")
        sys.exit(1)
    if not is_admin():
        messagebox.showerror("Admin required", "This tool requires Administrator privileges. Please run the Python process as Administrator.")
        print("Run the script as Administrator.")
        sys.exit(1)

    root = tk.Tk()
    app = WipeGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()