"""
Digital Signature Generation & Verification App
Requires: pip install cryptography
Run:      python digital_signature_app.py
"""
import os, json, hashlib, datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519
from cryptography.exceptions import InvalidSignature

LOG_FILE = "signature_log.json"
ALGOS = ["RSA-PSS", "ECDSA", "Ed25519"]


# ---------------------------------------------------------------- crypto core
def generate_key(algo):
    if algo == "RSA-PSS":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algo == "ECDSA":
        return ec.generate_private_key(ec.SECP256R1())
    return ed25519.Ed25519PrivateKey.generate()


def save_keys(key, folder, name, password):
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, enc)
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    pp, pu = os.path.join(folder, name + "_private.pem"), os.path.join(folder, name + "_public.pem")
    open(pp, "wb").write(priv)
    open(pu, "wb").write(pub)
    return pp, pu


def load_private(path, password):
    pw = password.encode() if password else None
    return serialization.load_pem_private_key(open(path, "rb").read(), pw)


def load_public(path):
    return serialization.load_pem_public_key(open(path, "rb").read())


def sign_data(key, data):
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    return key.sign(data)


def verify_data(pub, data, sig):
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                              salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(sig, data)
        return True
    except InvalidSignature:
        return False


def algo_name(key):
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)): return "RSA-PSS"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)): return "ECDSA"
    return "Ed25519"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_log(action, filename, algo, result):
    try:
        logs = json.load(open(LOG_FILE))
    except Exception:
        logs = []
    logs.append({"time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "action": action, "file": os.path.basename(filename),
                 "algorithm": algo, "result": result})
    json.dump(logs, open(LOG_FILE, "w"), indent=2)


# ------------------------------------------------------------------------ GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Digital Signature Generation & Verification")
        self.geometry("760x560")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tabs = {}
        for name, builder in [("1. Generate Keys", self.keys_tab), ("2. Sign", self.sign_tab),
                              ("3. Verify", self.verify_tab), ("4. Tamper Demo", self.demo_tab),
                              ("History", self.history_tab)]:
            f = ttk.Frame(nb, padding=12)
            nb.add(f, text=name)
            builder(f)
        nb.bind("<<NotebookTabChanged>>", lambda e: self.load_history())

    # helpers
    def file_row(self, parent, label, row, var, save=False, types=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=var, width=55).grid(row=row, column=1, padx=6)
        def browse():
            p = (filedialog.askdirectory() if save == "dir"
                 else filedialog.askopenfilename(filetypes=types or [("All files", "*.*")]))
            if p: var.set(p)
        ttk.Button(parent, text="Browse", command=browse).grid(row=row, column=2)

    def output(self, parent, row):
        box = tk.Text(parent, height=10, width=80, state="disabled", wrap="word")
        box.grid(row=row, column=0, columnspan=3, pady=10)
        return box

    def show(self, box, text):
        box.config(state="normal"); box.delete("1.0", "end")
        box.insert("end", text); box.config(state="disabled")

    # tab 1
    def keys_tab(self, f):
        self.k_algo, self.k_name = tk.StringVar(value="RSA-PSS"), tk.StringVar(value="mykey")
        self.k_pass, self.k_dir = tk.StringVar(), tk.StringVar(value=os.getcwd())
        ttk.Label(f, text="Algorithm").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Combobox(f, textvariable=self.k_algo, values=ALGOS, state="readonly").grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(f, text="Key name").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.k_name).grid(row=1, column=1, sticky="w", padx=6)
        ttk.Label(f, text="Password (optional)").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.k_pass, show="*").grid(row=2, column=1, sticky="w", padx=6)
        self.file_row(f, "Save to folder", 3, self.k_dir, save="dir")
        ttk.Button(f, text="Generate Key Pair", command=self.do_keys).grid(row=4, column=1, sticky="w", pady=10)
        self.k_out = self.output(f, 5)

    def do_keys(self):
        algo = self.k_algo.get()
        key = generate_key(algo)
        pp, pu = save_keys(key, self.k_dir.get(), self.k_name.get(), self.k_pass.get())
        self.show(self.k_out, f"Key pair generated ({algo})\n\nPrivate key: {pp}\nPublic key:  {pu}\n\n"
                  f"Private key protected by password: {'Yes' if self.k_pass.get() else 'No'}\n"
                  "Keep the private key secret. Share only the public key.")
        write_log("KEYGEN", pp, algo, "OK")

    # tab 2
    def sign_tab(self, f):
        self.s_file, self.s_key, self.s_pass = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.file_row(f, "File to sign", 0, self.s_file)
        self.file_row(f, "Private key (.pem)", 1, self.s_key, types=[("PEM", "*.pem")])
        ttk.Label(f, text="Key password").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.s_pass, show="*").grid(row=2, column=1, sticky="w", padx=6)
        ttk.Button(f, text="Sign File", command=self.do_sign).grid(row=3, column=1, sticky="w", pady=10)
        self.s_out = self.output(f, 4)

    def do_sign(self):
        try:
            data = open(self.s_file.get(), "rb").read()
            key = load_private(self.s_key.get(), self.s_pass.get())
            sig = sign_data(key, data)
        except TypeError:
            return messagebox.showerror("Error", "This private key is password-protected. Enter the password.")
        except ValueError:
            return messagebox.showerror("Error", "Wrong password or invalid key file.")
        except Exception as e:
            return messagebox.showerror("Error", str(e))
        path = self.s_file.get() + ".sig"
        open(path, "wb").write(sig)
        self.show(self.s_out, f"File signed successfully\n\nAlgorithm: {algo_name(key)}\n"
                  f"SHA-256 of file:\n{sha256(data)}\n\nSignature size: {len(sig)} bytes\n"
                  f"Signature saved to: {path}\n\nSignature (hex, first 64 chars):\n{sig.hex()[:64]}...")
        write_log("SIGN", self.s_file.get(), algo_name(key), "OK")

    # tab 3
    def verify_tab(self, f):
        self.v_file, self.v_sig, self.v_pub = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.file_row(f, "Received file", 0, self.v_file)
        self.file_row(f, "Signature (.sig)", 1, self.v_sig, types=[("Signature", "*.sig")])
        self.file_row(f, "Public key (.pem)", 2, self.v_pub, types=[("PEM", "*.pem")])
        ttk.Button(f, text="Verify Signature", command=self.do_verify).grid(row=3, column=1, sticky="w", pady=10)
        self.v_result = tk.Label(f, text="", font=("Arial", 20, "bold"))
        self.v_result.grid(row=4, column=0, columnspan=3)
        self.v_out = self.output(f, 5)

    def do_verify(self):
        try:
            data = open(self.v_file.get(), "rb").read()
            sig = open(self.v_sig.get(), "rb").read()
            pub = load_public(self.v_pub.get())
            ok = verify_data(pub, data, sig)
        except Exception as e:
            return messagebox.showerror("Error", str(e))
        self.v_result.config(text="VALID" if ok else "INVALID", fg="green" if ok else "red")
        self.show(self.v_out, f"SHA-256 of received file:\n{sha256(data)}\n\nAlgorithm: {algo_name(pub)}\n\n" +
                  ("The signature is authentic and the file has not been modified."
                   if ok else "Verification FAILED. The file was modified, or the wrong key or signature was used."))
        write_log("VERIFY", self.v_file.get(), algo_name(pub), "VALID" if ok else "INVALID")

    # tab 4
    def demo_tab(self, f):
        ttk.Label(f, text="Type a message, sign it, then change one character and verify again.",
                  font=("Arial", 10, "bold")).pack(anchor="w")
        self.d_text = tk.Text(f, height=6, width=80)
        self.d_text.insert("1.0", "Pay Rs. 1000 to Alice")
        self.d_text.pack(pady=8)
        bf = ttk.Frame(f); bf.pack()
        ttk.Button(bf, text="Sign Message", command=self.demo_sign).pack(side="left", padx=5)
        ttk.Button(bf, text="Verify Message", command=self.demo_verify).pack(side="left", padx=5)
        self.d_result = tk.Label(f, text="", font=("Arial", 20, "bold")); self.d_result.pack(pady=8)
        self.d_info = tk.Label(f, text="", justify="left", wraplength=700); self.d_info.pack()
        self.d_key, self.d_sig = generate_key("RSA-PSS"), None  # temporary demo key pair

    def demo_sign(self):
        msg = self.d_text.get("1.0", "end-1c").encode()
        self.d_sig = sign_data(self.d_key, msg)
        self.d_result.config(text="Signed", fg="blue")
        self.d_info.config(text=f"Hash: {sha256(msg)}\nNow edit the message above and press Verify.")

    def demo_verify(self):
        if not self.d_sig:
            return messagebox.showinfo("Info", "Sign the message first.")
        msg = self.d_text.get("1.0", "end-1c").encode()
        ok = verify_data(self.d_key.public_key(), msg, self.d_sig)
        self.d_result.config(text="VALID" if ok else "INVALID (tampered!)", fg="green" if ok else "red")
        self.d_info.config(text=f"Current hash: {sha256(msg)}")

    # tab 5
    def history_tab(self, f):
        cols = ("time", "action", "file", "algorithm", "result")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c.title()); self.tree.column(c, width=130)
        self.tree.pack(fill="both", expand=True)

    def load_history(self):
        self.tree.delete(*self.tree.get_children())
        try:
            for r in reversed(json.load(open(LOG_FILE))):
                self.tree.insert("", "end", values=(r["time"], r["action"], r["file"], r["algorithm"], r["result"]))
        except Exception:
            pass


if __name__ == "__main__":
    App().mainloop()
