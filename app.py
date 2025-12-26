# ============================================================
# Playfair + RSA GUI App (Professional Edition)
# - Modern Tkinter UI với dark/light theme
# - Playfair: encrypt/decrypt (I/J merged, X padding)
# - RSA: Miller-Rabin primality test, PKCS#1 v1.5 padding
# ============================================================

import base64
import math
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading

# ============================================================
# PLAYFAIR CIPHER
# ============================================================
ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J omitted

def normalize_text(s: str) -> str:
    """Normalize: uppercase, remove non-alpha, replace J→I"""
    s = "".join(ch for ch in s.upper() if ch.isalpha())
    return s.replace("J", "I")

def playfair_build_square(key: str):
    """Build 5x5 Playfair square from key"""
    key = normalize_text(key)
    seen = set()
    sq = []
    for ch in key + ALPHABET:
        if ch not in seen:
            seen.add(ch)
            sq.append(ch)
    
    grid = [sq[i*5:(i+1)*5] for i in range(5)]
    pos = {grid[r][c]: (r, c) for r in range(5) for c in range(5)}
    return grid, pos

def playfair_prepare_digraphs(plaintext: str):
    """Split plaintext into digraphs with X padding"""
    t = normalize_text(plaintext)
    if not t:
        return []
    
    digraphs = []
    i = 0
    while i < len(t):
        a = t[i]
        if i + 1 < len(t):
            b = t[i + 1]
            if a == b:
                digraphs.append((a, "X"))
                i += 1
            else:
                digraphs.append((a, b))
                i += 2
        else:
            digraphs.append((a, "X"))
            i += 1
    return digraphs

def playfair_encrypt(plaintext: str, key: str) -> str:
    """Encrypt using Playfair cipher"""
    grid, pos = playfair_build_square(key)
    pairs = playfair_prepare_digraphs(plaintext)
    out = []
    
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        
        if ra == rb:  # Same row
            out.append(grid[ra][(ca + 1) % 5])
            out.append(grid[rb][(cb + 1) % 5])
        elif ca == cb:  # Same column
            out.append(grid[(ra + 1) % 5][ca])
            out.append(grid[(rb + 1) % 5][cb])
        else:  # Rectangle
            out.append(grid[ra][cb])
            out.append(grid[rb][ca])
    
    return "".join(out)

def playfair_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt using Playfair cipher"""
    grid, pos = playfair_build_square(key)
    ct = normalize_text(ciphertext)
    
    if len(ct) % 2 != 0:
        raise ValueError("Ciphertext phải có độ dài chẵn")
    
    out = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i+1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        
        if ra == rb:  # Same row
            out.append(grid[ra][(ca - 1) % 5])
            out.append(grid[rb][(cb - 1) % 5])
        elif ca == cb:  # Same column
            out.append(grid[(ra - 1) % 5][ca])
            out.append(grid[(rb - 1) % 5][cb])
        else:  # Rectangle
            out.append(grid[ra][cb])
            out.append(grid[rb][ca])
    
    return "".join(out)

def playfair_square_string(key: str) -> str:
    """Return visual representation of Playfair square"""
    grid, _ = playfair_build_square(key)
    return "\n".join("  ".join(grid[r]) for r in range(5))

# ============================================================
# RSA CRYPTOGRAPHY
# ============================================================
def egcd(a, b):
    """Extended Euclidean Algorithm"""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a, m):
    """Modular inverse using EGCD"""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse không tồn tại")
    return x % m

def is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # write n-1 = d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        
        if composite:
            return False
    
    return True

def gen_prime(bits: int) -> int:
    """Generate random prime with specified bit length"""
    if bits < 256:
        raise ValueError("bits phải >= 256")
    
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def rsa_generate_keypair(bits: int = 2048):
    """Generate RSA keypair (n, e, d)"""
    e = 65537
    half = bits // 2
    
    while True:
        p = gen_prime(half)
        q = gen_prime(bits - half)
        if p == q:
            continue
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return (n, e, d)

def i2osp(x: int, xlen: int) -> bytes:
    """Integer to Octet String Primitive"""
    if x >= 256 ** xlen:
        raise ValueError("Integer too large")
    return x.to_bytes(xlen, "big")

def os2ip(b: bytes) -> int:
    """Octet String to Integer Primitive"""
    return int.from_bytes(b, "big")

def rsa_encrypt_pkcs1_v15(message: bytes, n: int, e: int) -> bytes:
    """RSA encrypt with PKCS#1 v1.5 padding"""
    k = (n.bit_length() + 7) // 8
    if len(message) > k - 11:
        raise ValueError(f"Message quá dài (max {k-11} bytes)")
    
    # EM = 0x00 || 0x02 || PS || 0x00 || M
    ps_len = k - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.randbelow(256)
        if b != 0:
            ps.append(b)
    
    em = b"\x00\x02" + bytes(ps) + b"\x00" + message
    c = pow(os2ip(em), e, n)
    return i2osp(c, k)

def rsa_decrypt_pkcs1_v15(ciphertext: bytes, n: int, d: int) -> bytes:
    """RSA decrypt with PKCS#1 v1.5 padding"""
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("Ciphertext length không khớp")
    
    m = pow(os2ip(ciphertext), d, n)
    em = i2osp(m, k)
    
    if not (len(em) >= 11 and em[0] == 0x00 and em[1] == 0x02):
        raise ValueError("Padding không hợp lệ")
    
    try:
        sep = em.index(b"\x00", 2)
    except ValueError:
        raise ValueError("Separator không tìm thấy")
    
    if sep < 10:
        raise ValueError("PS quá ngắn")
    
    return em[sep + 1:]

# ============================================================
# GUI APPLICATION
# ============================================================
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Crypto Lab - Playfair & RSA")
        self.geometry("1200x800")
        self.configure(bg="#f5f5f5")
        
        # RSA state
        self.rsa_n = None
        self.rsa_e = None
        self.rsa_d = None
        
        self._setup_style()
        self._build_ui()
        self._center_window()
    
    def _center_window(self):
        """Center window on screen"""
        self.update_idletasks()
        w, h = 1200, 800
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
    
    def _setup_style(self):
        """Configure light theme styling"""
        style = ttk.Style()
        style.theme_use("clam")
        
        bg, fg = "#f5f5f5", "#1a1a1a"
        accent = "#0066ff"
        
        style.configure("TNotebook", background=bg, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(20, 10))
        style.map("TNotebook.Tab",
                  background=[("selected", "#ffffff"), ("!selected", "#f5f5f5")],
                  foreground=[("selected", accent), ("!selected", fg)])
        
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"), background=bg, foreground=accent)
        style.configure("TButton", font=("Segoe UI", 10))
        style.map("TButton",
                  background=[("active", accent), ("!disabled", "#e8e8e8")],
                  foreground=[("!disabled", fg)])
    
    def _build_ui(self):
        """Build main UI"""
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        
        tab_pf = ttk.Frame(nb)
        tab_rsa = ttk.Frame(nb)
        nb.add(tab_pf, text="🔐 Playfair")
        nb.add(tab_rsa, text="🗝️ RSA")
        
        self._build_playfair(tab_pf)
        self._build_rsa(tab_rsa)
    
    def _build_playfair(self, parent):
        """Playfair cipher UI"""
        main = ttk.Frame(parent)
        main.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel
        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ttk.Label(left, text="Input", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Key input
        ttk.Label(left, text="Key:").pack(anchor="w")
        self.pf_key = tk.StringVar(value="MONARCHY")
        ttk.Entry(left, textvariable=self.pf_key).pack(fill="x", pady=(0, 15))
        
        # Message input
        ttk.Label(left, text="Text (Plaintext/Ciphertext):").pack(anchor="w")
        self.pf_input = scrolledtext.ScrolledText(left, height=15, width=40, bg="#ffffff", fg="#1a1a1a", font=("Consolas", 10))
        self.pf_input.pack(fill="both", expand=True, pady=(0, 15))
        
        # Buttons
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Encrypt", command=self._pf_encrypt).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self._pf_decrypt).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: self.pf_input.delete("1.0", "end")).pack(side="right")
        
        # Right panel
        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        
        ttk.Label(right, text="Output", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        self.pf_output = scrolledtext.ScrolledText(right, height=15, width=40, bg="#ffffff", fg="#0066ff", font=("Consolas", 10))
        self.pf_output.pack(fill="both", expand=True, pady=(0, 15))
        
        ttk.Button(right, text="Copy Output", command=lambda: self._copy_clipboard(self.pf_output.get("1.0", "end").strip())).pack(fill="x", pady=(0, 10))
        
        # Key square
        ttk.Label(right, text="Key Square (5×5):").pack(anchor="w")
        self.pf_square = tk.Text(right, height=6, bg="#ffffff", fg="#1a1a1a", font=("Consolas", 11))
        self.pf_square.pack(fill="x")
        
        self.pf_key.trace_add("write", self._update_square)
    
    def _update_square(self, var=None, index=None, mode=None):
        """Update Playfair square display"""
        key = self.pf_key.get().strip() or "KEY"
        sq = playfair_square_string(key)
        self.pf_square.delete("1.0", "end")
        self.pf_square.insert("1.0", sq)
    
    def _pf_encrypt(self):
        """Encrypt Playfair"""
        key = self.pf_key.get().strip()
        text = self.pf_input.get("1.0", "end").strip()
        
        if not key or not text:
            messagebox.showwarning("Input không đủ", "Nhập Key và Text")
            return
        
        try:
            result = playfair_encrypt(text, key)
            self.pf_output.delete("1.0", "end")
            self.pf_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
    
    def _pf_decrypt(self):
        """Decrypt Playfair"""
        key = self.pf_key.get().strip()
        text = self.pf_input.get("1.0", "end").strip()
        
        if not key or not text:
            messagebox.showwarning("Input không đủ", "Nhập Key và Ciphertext")
            return
        
        try:
            result = playfair_decrypt(text, key)
            self.pf_output.delete("1.0", "end")
            self.pf_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
    
    def _build_rsa(self, parent):
        """RSA cryptography UI"""
        main = ttk.Frame(parent)
        main.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left: Key generation
        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ttk.Label(left, text="Key Generation", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Key size selector
        size_frame = ttk.Frame(left)
        size_frame.pack(fill="x", pady=(0, 15))
        ttk.Label(size_frame, text="Key size:").pack(side="left")
        self.rsa_bits = tk.StringVar(value="2048")
        ttk.Combobox(size_frame, textvariable=self.rsa_bits, values=["1024", "2048"], width=10, state="readonly").pack(side="left", padx=10)
        ttk.Button(size_frame, text="Generate", command=self._rsa_generate).pack(side="left")
        
        # Public key
        ttk.Label(left, text="Public Key (n, e):").pack(anchor="w")
        self.rsa_pub = scrolledtext.ScrolledText(left, height=6, bg="#ffffff", fg="#1a1a1a", font=("Consolas", 9))
        self.rsa_pub.pack(fill="both", expand=True, pady=(0, 10))
        
        # Private key
        ttk.Label(left, text="Private Key (d):").pack(anchor="w")
        self.rsa_priv = scrolledtext.ScrolledText(left, height=4, bg="#ffffff", fg="#d32f2f", font=("Consolas", 9))
        self.rsa_priv.pack(fill="both", expand=True, pady=(0, 10))
        
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Copy Pub", command=lambda: self._copy_clipboard(self.rsa_pub.get("1.0", "end").strip())).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Copy Priv", command=lambda: self._copy_clipboard(self.rsa_priv.get("1.0", "end").strip())).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", command=self._rsa_clear).pack(side="right")
        
        # Right: Encrypt/Decrypt
        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        
        ttk.Label(right, text="Encrypt / Decrypt", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        ttk.Label(right, text="Message:").pack(anchor="w")
        self.rsa_msg = scrolledtext.ScrolledText(right, height=7, bg="#ffffff", fg="#1a1a1a", font=("Consolas", 10))
        self.rsa_msg.pack(fill="both", expand=True, pady=(0, 10))
        
        action = ttk.Frame(right)
        action.pack(fill="x", pady=(0, 10))
        ttk.Button(action, text="Encrypt", command=self._rsa_encrypt).pack(side="left", padx=5)
        ttk.Button(action, text="Decrypt", command=self._rsa_decrypt).pack(side="left", padx=5)
        
        ttk.Label(right, text="Result (Base64):").pack(anchor="w")
        self.rsa_out = scrolledtext.ScrolledText(right, height=7, bg="#ffffff", fg="#0066ff", font=("Consolas", 10))
        self.rsa_out.pack(fill="both", expand=True, pady=(0, 10))
        
        ttk.Button(right, text="Copy Result", command=lambda: self._copy_clipboard(self.rsa_out.get("1.0", "end").strip())).pack(fill="x")
    
    def _rsa_generate(self):
        """Generate RSA keys in background thread"""
        bits = int(self.rsa_bits.get())
        
        def generate():
            try:
                self.config(cursor="watch")
                n, e, d = rsa_generate_keypair(bits)
                self.rsa_n, self.rsa_e, self.rsa_d = n, e, d
                
                self.rsa_pub.delete("1.0", "end")
                self.rsa_pub.insert("1.0", f"n = {n}\n\ne = {e}\n\nBits: {bits}")
                
                self.rsa_priv.delete("1.0", "end")
                self.rsa_priv.insert("1.0", f"d = {d}\n\n⚠️ KEEP SECRET")
                
                messagebox.showinfo("Success", f"Generated {bits}-bit RSA keys")
                self.config(cursor="")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.config(cursor="")
        
        threading.Thread(target=generate, daemon=True).start()
    
    def _rsa_encrypt(self):
        """RSA encrypt"""
        if not (self.rsa_n and self.rsa_e):
            messagebox.showwarning("No keys", "Generate keys first")
            return
        
        msg = self.rsa_msg.get("1.0", "end").strip()
        if not msg:
            messagebox.showwarning("No message", "Enter message to encrypt")
            return
        
        try:
            pt = msg.encode("utf-8")
            ct = rsa_encrypt_pkcs1_v15(pt, self.rsa_n, self.rsa_e)
            ct_b64 = base64.b64encode(ct).decode("ascii")
            
            self.rsa_out.delete("1.0", "end")
            self.rsa_out.insert("1.0", ct_b64)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _rsa_decrypt(self):
        """RSA decrypt"""
        if not (self.rsa_n and self.rsa_d):
            messagebox.showwarning("No keys", "Generate keys first")
            return
        
        inp = self.rsa_msg.get("1.0", "end").strip()
        if not inp:
            messagebox.showwarning("No ciphertext", "Enter Base64 ciphertext")
            return
        
        try:
            ct = base64.b64decode(inp)
            pt = rsa_decrypt_pkcs1_v15(ct, self.rsa_n, self.rsa_d)
            text = pt.decode("utf-8")
            
            self.rsa_out.delete("1.0", "end")
            self.rsa_out.insert("1.0", text)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _rsa_clear(self):
        """Clear RSA keys and outputs"""
        self.rsa_n = self.rsa_e = self.rsa_d = None
        self.rsa_pub.delete("1.0", "end")
        self.rsa_priv.delete("1.0", "end")
        self.rsa_msg.delete("1.0", "end")
        self.rsa_out.delete("1.0", "end")
    
    def _copy_clipboard(self, text):
        """Copy to clipboard"""
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Text copied to clipboard")

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
