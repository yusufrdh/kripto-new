import hashlib
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP # New import for RSA
from Crypto.PublicKey import RSA # New import for RSA
from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad # GCM tidak memerlukannya
from PIL import Image
import base64
import json
import os
import functools
from io import BytesIO
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
    send_file,
)
from werkzeug.utils import secure_filename
import numpy as np # New import for LSB pixel manipulation

# --- Konfigurasi Flask ---
app = Flask(__name__)
app.secret_key = "kripto_secure_app" 
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["GENERATED_FOLDER"] = "generated"
app.config["DB_FOLDER"] = "database"

# Buat folder jika belum ada
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["GENERATED_FOLDER"], exist_ok=True)
os.makedirs(app.config["DB_FOLDER"], exist_ok=True)

# Kunci Vigenere Tetap untuk Enkripsi Teks
VIGENERE_KEY = "CRYPTOGRAPHY"

# Path Kunci RSA
RSA_PRIVATE_KEY_PATH = os.path.join(app.config["DB_FOLDER"], "rsa_private.pem")
RSA_PUBLIC_KEY_PATH = os.path.join(app.config["DB_FOLDER"], "rsa_public.pem")


# =====================================================================
# FUNGSI HELPER (Database JSON - Tidak Berubah)
# =====================================================================

def get_user_db_path():
    return os.path.join(app.config["DB_FOLDER"], "users.json")

def get_history_db_path():
    return os.path.join(app.config["DB_FOLDER"], "history.json")

def load_data(db_path):
    """Memuat data dari file JSON."""
    if os.path.exists(db_path):
        try:
            with open(db_path, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            return {}
    return {}

def save_data(data, db_path):
    """Menyimpan data ke file JSON."""
    with open(db_path, "w") as file:
        json.dump(data, file, indent=4)

def add_history(username, action, original_file, generated_file=None):
    """Menambahkan catatan ke history.json."""
    db_path = get_history_db_path()
    history_data = load_data(db_path)
    
    if username not in history_data:
        history_data[username] = []
        
    history_data[username].append({
        "action": action,
        "original_file": original_file,
        "generated_file": generated_file,
        "timestamp": base64.b64encode(get_random_bytes(6)).decode('utf-8')
    })
    save_data(history_data, db_path)

# =====================================================================
# FUNGSI HELPER (Kriptografi & Steganografi BARU)
# =====================================================================

# --- 1. LOGIN (SHA-3) ---
def hash_data(data):
    """Hash password menggunakan SHA3-256."""
    return hashlib.sha3_256(data.encode()).hexdigest()

# --- 2. AES KEY UTAMA & PENYIMPANAN ---
# AES Key (32 bytes = 256-bit) digunakan untuk Enkripsi Profil, Teks, dan Steganografi
def save_key(key, filename="aes_key.bin"):
    """Menyimpan AES key."""
    key_path = os.path.join(app.config["DB_FOLDER"], filename)
    with open(key_path, "wb") as file:
        file.write(key)

def load_key(filename="aes_key.bin"):
    """Memuat AES key."""
    key_path = os.path.join(app.config["DB_FOLDER"], filename)
    if os.path.exists(key_path):
        with open(key_path, "rb") as file:
            return file.read()
    return None

# --- 3. AES-256 GCM (Untuk Profil, Teks, Steganografi, Hybrid File) ---
def aes_encrypt_gcm(key, data_bytes):
    """Enkripsi data (bytes) menggunakan AES GCM (256-bit)."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    # Mengembalikan Nonce + Tag + Ciphertext
    return cipher.nonce + tag + ciphertext

def aes_decrypt_gcm(key, ciphertext_with_nonce_tag):
    """Dekripsi data (bytes) dari AES GCM (256-bit)."""
    NONCE_LEN = 16
    TAG_LEN = 16
    
    nonce = ciphertext_with_nonce_tag[:NONCE_LEN]
    tag = ciphertext_with_nonce_tag[NONCE_LEN:NONCE_LEN + TAG_LEN]
    ciphertext = ciphertext_with_nonce_tag[NONCE_LEN + TAG_LEN:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# --- 4. VIGENERE CIPHER (Bagian dari Algoritma Teks Super) ---
def vigenere_encrypt(plaintext, key):
    """Enkripsi menggunakan Vigenere."""
    key = key.upper().replace(" ", "")
    key_len = len(key)
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if 'A' <= char.upper() <= 'Z':
            shift = ord(key[key_index % key_len]) - ord('A')
            
            if 'a' <= char <= 'z':
                ciphertext += chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            elif 'A' <= char <= 'Z':
                ciphertext += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            
            key_index += 1
        else:
            ciphertext += char
            
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    """Dekripsi menggunakan Vigenere."""
    key = key.upper().replace(" ", "")
    key_len = len(key)
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if 'A' <= char.upper() <= 'Z':
            shift = ord(key[key_index % key_len]) - ord('A')
            
            if 'a' <= char <= 'z':
                plaintext += chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
            elif 'A' <= char <= 'Z':
                plaintext += chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
            
            key_index += 1
        else:
            plaintext += char
            
    return plaintext

# --- 5. LSB (Untuk Steganografi) ---
def to_bit_array(data):
    """Helper: Konversi bytes ke array bit."""
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    return bits

def from_bit_array(bits):
    """Helper: Konversi array bit ke bytes."""
    if len(bits) % 8 != 0:
        bits = np.pad(bits, (0, 8 - (len(bits) % 8)), 'constant', constant_values=0)
    return np.packbits(bits).tobytes()

def lsb_hide(image_stream, secret_bytes, output_stream):
    """LSB 256 GCM: Menyembunyikan pesan di 1 bit LSB (dari stream ke stream)."""
    try:
        img = Image.open(image_stream).convert("RGB") # MODIFIED: Baca dari stream
        img_np = np.array(img)
        
        data_len = len(secret_bytes)
        len_bytes = data_len.to_bytes(4, byteorder='big')
        full_data = len_bytes + secret_bytes
        data_bits = to_bit_array(full_data)
        
        required_pixels = len(data_bits) // 3 + (1 if len(data_bits) % 3 > 0 else 0)
        max_pixels = img_np.shape[0] * img_np.shape[1]
        
        if required_pixels > max_pixels:
            raise ValueError(f"Pesan terlalu besar. Perlu {required_pixels} piksel.")
        
        data_index = 0
        # Iterasi dan Sembunyikan bit di LSB
        for i in range(img_np.shape[0]):
            for j in range(img_np.shape[1]):
                pixel = img_np[i, j]
                new_pixel = pixel.copy()
                
                for k in range(3): # R, G, B channels
                    if data_index < len(data_bits):
                        # Ganti LSB
                        new_pixel[k] = (pixel[k] & 0xFE) | data_bits[data_index]
                        data_index += 1
                
                img_np[i, j] = new_pixel
                if data_index >= len(data_bits):
                    break
            if data_index >= len(data_bits):
                break
                
        new_img = Image.fromarray(img_np, 'RGB')
        new_img.save(output_stream, "PNG") # MODIFIED: Tulis ke stream
        return True
    except Exception as e:
        print(f"Error lsb_hide: {e}")
        return False

# GANTI FUNGSI INI
def lsb_retrieve(image_stream):
    """LSB 256 GCM: Mengambil pesan tersembunyi (dari stream)."""
    try:
        img = Image.open(image_stream).convert("RGB") # MODIFIED: Baca dari stream
        img_np = np.array(img)
        
        # 1. Ambil panjang data (32 bits = 4 bytes)
        len_bits = []
        data_index = 0
        found_length = False
        
        for i in range(img_np.shape[0]):
            for j in range(img_np.shape[1]):
                pixel = img_np[i, j]
                for k in range(3): 
                    len_bits.append(pixel[k] & 0x01)
                    data_index += 1
                    if len(len_bits) == 32:
                        found_length = True
                        break
                if found_length: break
            if found_length: break
        
        if len(len_bits) < 32: return None 
             
        len_bytes = from_bit_array(np.array(len_bits, dtype=np.uint8))
        data_len = int.from_bytes(len_bytes, byteorder='big')
        
        # 2. Ambil pesan (data_len * 8 bits)
        required_bits = data_len * 8
        secret_bits = []
        
        start_pixel_idx = data_index // 3
        start_channel_idx = data_index % 3

        for i in range(img_np.shape[0]):
            for j in range(img_np.shape[1]):
                if i * img_np.shape[1] + j < start_pixel_idx: continue
                    
                pixel = img_np[i, j]
                start_k = start_channel_idx if i * img_np.shape[1] + j == start_pixel_idx else 0
                
                for k in range(start_k, 3):
                    if len(secret_bits) < required_bits:
                        secret_bits.append(pixel[k] & 0x01)
                    else:
                        break
                if len(secret_bits) >= required_bits: break
            if len(secret_bits) >= required_bits: break

        if len(secret_bits) < required_bits:
            raise Exception("Pesan terpotong atau gambar rusak.")
            
        # 3. Konversi bit pesan menjadi bytes
        secret_bytes = from_bit_array(np.array(secret_bits, dtype=np.uint8))
        return secret_bytes
        
    except Exception as e:
        print(f"Error lsb_retrieve: {e}")
        return None

# --- 6. RSA KEY MANAGEMENT (Untuk File Algorithm) ---
def generate_rsa_keys():
    """Menghasilkan pasangan kunci RSA (2048-bit)."""
    if not os.path.exists(RSA_PRIVATE_KEY_PATH):
        print("Generating new RSA keys...")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        with open(RSA_PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key)
        with open(RSA_PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key)

def load_rsa_keys():
    """Memuat kunci RSA publik dan privat."""
    private_key = public_key = None
    try:
        with open(RSA_PRIVATE_KEY_PATH, "rb") as f:
            private_key = RSA.import_key(f.read())
        with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
            public_key = RSA.import_key(f.read())
    except FileNotFoundError:
        generate_rsa_keys()
        return load_rsa_keys()
    except Exception as e:
        print(f"Error loading RSA keys: {e}. Generating new keys.")
        generate_rsa_keys()
        return load_rsa_keys()
        
    return private_key, public_key
# -------------------------------------------------------------
# FUNGSI HELPER BARU UNTUK OTORITAS
# -------------------------------------------------------------
def is_admin():
    """Memeriksa apakah user yang sedang login adalah admin."""
    if "username" not in session:
        return False
    username = session["username"]
    user_db = load_data(get_user_db_path())
    # Memastikan data role ada, jika tidak ada dianggap member
    return user_db.get(username, {}).get("role") == "admin"
# -------------------------------------------------------------


# =====================================================================
# PEMUATAN AWAL APLIKASI
# =====================================================================

# Memuat atau membuat AES key utama (Sekarang AES-256)
aes_key = load_key()
if aes_key is None or len(aes_key) != 32: 
    aes_key = get_random_bytes(32) # AES-256 (32 bytes)
    save_key(aes_key)

# Memuat atau membuat pasangan kunci RSA
private_rsa_key, public_rsa_key = load_rsa_keys()

# =====================================================================
# DECORATOR (PENGECEK LOGIN - Tidak Berubah)
# =====================================================================

def login_required(f):
    """Decorator untuk halaman yang memerlukan login."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session: 
            flash("Anda harus login untuk mengakses halaman ini.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# =====================================================================
# RUTE UTAMA (Index, Login, Register, Logout)
# =====================================================================

# Fungsi dekripsi helper (menggunakan AES-256 GCM)
def decrypt_profile_data(encrypted_b64):
    """Dekripsi data Base64 terenkripsi menjadi string menggunakan AES-256 GCM."""
    if not encrypted_b64:
        return None
    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        decrypted_bytes = aes_decrypt_gcm(aes_key, encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error dekripsi data: {e}")
        return None

@app.route("/")
def index():
    """Halaman utama / landing page."""
    display_name = "Pengguna"
    if "logged_in" in session:
        username = session["username"]
        user_db = load_data(get_user_db_path())
        decrypted_fullname = None
        if username in user_db and user_db[username].get("fullname"):
            encrypted_fn_b64 = user_db[username]["fullname"]
            decrypted_fullname = decrypt_profile_data(encrypted_fn_b64)
        if decrypted_fullname:
            display_name = decrypted_fullname
        else:
            display_name = username
        return render_template("index.html", display_name=display_name)
    return render_template("index.html", display_name=display_name)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Halaman login user (menggunakan SHA3-256)."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_db = load_data(get_user_db_path())
        
        # MENGGUNAKAN SHA3-256
        if username in user_db and user_db[username]["password"] == hash_data(password):
            session["logged_in"] = True
            session["username"] = username
            flash("Login berhasil! Selamat datang.", "success")
            return redirect(url_for("index")) 
        else:
            flash("Login gagal! Username atau password salah.", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Halaman registrasi user (menggunakan SHA3-256)."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_db = load_data(get_user_db_path())
        
        if username in user_db:
            flash("Username sudah terdaftar, silakan gunakan username lain.", "error")
            return redirect(url_for("register"))
            
        # MENGGUNAKAN SHA3-256
        user_db[username] = {
            "password": hash_data(password),
            "role": "member" # MODIFIED: Tambahkan role default 'member'
        }
        save_data(user_db, get_user_db_path())
        
        flash("Registrasi berhasil! Silakan login.", "success")
        return redirect(url_for("login"))
        
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    """Proses logout user."""
    session.clear()
    flash("Anda telah berhasil logout.", "success")
    return redirect(url_for("login"))

# =====================================================================
# RUTE FITUR APLIKASI (Modifikasi Enkripsi/Dekripsi)
# =====================================================================

@app.route("/profile") 
@login_required
def profile_dashboard():
    """Halaman dashboard profil (menampilkan data terdekripsi)."""
    
    username = session["username"]
    user_db = load_data(get_user_db_path())
    user_data = user_db.get(username, {})
    
    def decrypt_profile_data_safe(encrypted_b64):
        """Dekripsi data Base64 terenkripsi menjadi string untuk tampilan."""
        if not encrypted_b64:
            return "Belum Diisi"
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
            decrypted_bytes = aes_decrypt_gcm(aes_key, encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            print(f"Error dekripsi data: {e}")
            return "Data Error/Belum Diisi"

    decrypted_fullname = decrypt_profile_data_safe(user_data.get("fullname"))
    decrypted_email = decrypt_profile_data_safe(user_data.get("email"))
    decrypted_phone = decrypt_profile_data_safe(user_data.get("phone"))
    
    display_name = decrypted_fullname if decrypted_fullname != "Belum Diisi" else username

    is_admin_user = is_admin()
    
    return render_template(
        "profile_dashboard.html", 
        display_name=display_name,
        fullname=decrypted_fullname,
        email=decrypted_email,
        phone=decrypted_phone,
        is_admin_user=is_admin_user
    )

@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    """Halaman untuk mengedit data profil."""
    
    username = session["username"]
    user_db = load_data(get_user_db_path())
    user_data = user_db.get(username, {})
    
    if request.method == "POST":
        try:
            fullname = request.form.get("fullname")
            email = request.form.get("email")
            phone = request.form.get("phone")
            
            if username in user_db:
                # ENKRIPSI DATA SEBELUM DISIMPAN (MENGGUNAKAN AES-256 GCM)
                fn_bytes = fullname.encode('utf-8')
                encrypted_fn = aes_encrypt_gcm(aes_key, fn_bytes)
                user_db[username]["fullname"] = base64.b64encode(encrypted_fn).decode('utf-8')
                
                em_bytes = email.encode('utf-8')
                encrypted_em = aes_encrypt_gcm(aes_key, em_bytes)
                user_db[username]["email"] = base64.b64encode(encrypted_em).decode('utf-8')
                
                ph_bytes = phone.encode('utf-8')
                encrypted_ph = aes_encrypt_gcm(aes_key, ph_bytes)
                user_db[username]["phone"] = base64.b64encode(encrypted_ph).decode('utf-8')
                
                save_data(user_db, get_user_db_path())
                flash("Profil berhasil diperbarui dan dienkripsi!", "success")
            else:
                flash("Gagal memperbarui profil: Pengguna tidak ditemukan.", "error")
                
            return redirect(url_for("profile_dashboard")) 
        except Exception as e:
            flash(f"Terjadi error saat menyimpan profil: {e}", "error")
            return redirect(url_for("edit_profile"))

    # DEKRIPSI DATA SAAT DIMUAT UNTUK FORM (GET)
    decrypted_fullname = decrypted_email = decrypted_phone = ""
    
    try:
        def decrypt_form_data(encrypted_b64):
            if encrypted_b64:
                encrypted_bytes = base64.b64decode(encrypted_b64)
                return aes_decrypt_gcm(aes_key, encrypted_bytes).decode('utf-8')
            return ""
            
        decrypted_fullname = decrypt_form_data(user_data.get("fullname"))
        decrypted_email = decrypt_form_data(user_data.get("email"))
        decrypted_phone = decrypt_form_data(user_data.get("phone"))
            
    except Exception as e:
        print(f"Error saat dekripsi profil: {e}. Menggunakan data mentah/kosong.")
        flash("Data profil Anda perlu diperbarui untuk proses enkripsi yang baru. Harap Simpan Profil.", "warning")
            
    return render_template(
        "edit_profile.html", 
        fullname=decrypted_fullname,
        email=decrypted_email,
        phone=decrypted_phone
    )

@app.route("/encrypt_text", methods=["GET", "POST"])
@login_required
def encrypt_text():
    """Halaman untuk enkripsi DAN dekripsi teks (Vigenere + AES-256 GCM)."""
    
    # Variabel untuk dikirim ke template
    result_text = None
    input_text = "" # Untuk menyimpan input pengguna agar tidak hilang
    
    if request.method == "POST":
        try:
            # Ambil aksi (tombol 'encrypt' atau 'decrypt')
            action = request.form.get("action") 
            input_text = request.form.get("text_input", "")
            
            if not input_text:
                flash("Teks input tidak boleh kosong.", "error")
                return render_template("encrypt_text.html", input_text=input_text, result_text=result_text)

            # --- LOGIKA ENKRIPSI ---
            if action == "encrypt":
                # 1. Enkripsi Vigenere
                vigenere_ciphertext = vigenere_encrypt(input_text, VIGENERE_KEY)
                
                # 2. Enkripsi AES-256 GCM
                text_bytes = vigenere_ciphertext.encode('utf-8')
                encrypted_data = aes_encrypt_gcm(aes_key, text_bytes)
                
                result_text = base64.b64encode(encrypted_data).decode('utf-8')
                
                flash("Teks berhasil dienkripsi dengan Vigenere + AES-256 GCM!", "success")
                add_history(session["username"], "Encrypt Text (Vigenere+AES)", input_text[:30]+"")
            
            # --- LOGIKA DEKRIPSI (BARU) ---
            elif action == "decrypt":
                try:
                    # 1. Decode Base64
                    encrypted_data = base64.b64decode(input_text)
                    
                    # 2. Dekripsi AES-256 GCM
                    decrypted_vigenere_bytes = aes_decrypt_gcm(aes_key, encrypted_data)
                    decrypted_vigenere_text = decrypted_vigenere_bytes.decode('utf-8')
                    
                    # 3. Dekripsi Vigenere
                    result_text = vigenere_decrypt(decrypted_vigenere_text, VIGENERE_KEY)
                    
                    flash("Teks berhasil didekripsi!", "success")
                    add_history(session["username"], "Decrypt Text (AES+Vigenere)", input_text[:30]+"")
                    
                except Exception as e:
                    print(f"Error dekripsi: {e}")
                    flash("Dekripsi gagal. Pastikan teks Base64 valid dan kunci benar.", "error")
                    result_text = None

        except Exception as e:
            flash(f"Terjadi error: {e}", "error")
            
    # Kirim variabel 'result_text' dan 'input_text' ke template
    return render_template(
        "encrypt_text.html", 
        result_text=result_text,
        input_text=input_text 
    )


# GANTI SELURUH RUTE INI
@app.route("/encrypt_image", methods=["GET", "POST"])
@login_required
def encrypt_image():
    """Halaman steganografi (AES-256 GCM + LSB) - VERSI AMAN (IN-MEMORY)."""
    
    # Ini hanya digunakan untuk bagian dekripsi
    decrypted_message = None 
    
    if request.method == "POST":
        action = request.form.get("action") 
        
        # --- LOGIKA ENKRIPSI (AES-256 GCM + LSB Hiding) ---
        if action == "encrypt":
            try:
                if "image" not in request.files or "message" not in request.form:
                    flash("Harap masukkan file gambar dan pesan rahasia.", "error")
                    return redirect(request.url)
                    
                file = request.files["image"]
                message = request.form["message"]
                
                if file.filename == "" or message == "":
                    flash("File atau pesan tidak boleh kosong.", "error")
                    return redirect(request.url)
                
                # Ambil nama file asli untuk output
                filename = secure_filename(file.filename)
                name_only = os.path.splitext(filename)[0]
                output_filename = f"stego_lsb_{name_only}.png"
                
                # 1. Enkripsi Pesan (AES-256 GCM)
                message_bytes = message.encode('utf-8')
                encrypted_message = aes_encrypt_gcm(aes_key, message_bytes)
                
                # --- PERUBAHAN KEAMANAN ---
                # Buat file di memori
                img_in_memory = BytesIO()

                # 2. Proses Steganografi (LSB) dari stream ke stream
                # (Gunakan file.stream untuk membaca file yg diupload tanpa menyimpan)
                # JANGAN simpan file input ke 'uploads'
                if not lsb_hide(file.stream, encrypted_message, img_in_memory):
                    raise Exception("Gagal melakukan steganografi LSB. Mungkin pesan terlalu besar.")
                
                # Pindahkan pointer ke awal file di memori
                img_in_memory.seek(0)
                
                # Catat history SEBELUM mengirim file
                add_history(session["username"], "LSB Stego Encrypt", filename, output_filename + " (in-memory)")
                
                # 3. Langsung kirim file ke pengguna, JANGAN SIMPAN KE 'generated'
                return send_file(
                    img_in_memory,
                    download_name=output_filename,
                    as_attachment=True,
                    mimetype='image/png'
                )
                # --- AKHIR PERUBAHAN ---
                
            except Exception as e:
                flash(f"Terjadi error: {e}", "error")
                return redirect(request.url) # Redirect jika error

        # --- LOGIKA DEKRIPSI (LSB Retrieval + AES-256 GCM Decrypt) ---
        elif action == "decrypt":
            try:
                file = request.files.get("decrypt_image") 
                
                if not file or file.filename == "":
                    flash("Harap pilih gambar yang mengandung pesan rahasia.", "error")
                    return redirect(request.url)

                filename = secure_filename(file.filename)
                
                # --- PERUBAHAN KEAMANAN ---
                # 1. Proses Pengambilan Pesan (LSB Retrieve) dari stream
                # JANGAN simpan file input ke 'uploads'
                encrypted_message = lsb_retrieve(file.stream)
                # --- AKHIR PERUBAHAN ---

                if encrypted_message:
                    # 2. Dekripsi Pesan (AES-256 GCM)
                    decrypted_bytes = aes_decrypt_gcm(aes_key, encrypted_message)
                    decrypted_message = decrypted_bytes.decode('utf-8')
                    
                    flash("Pesan rahasia berhasil ditemukan dan didekripsi!", "success")
                    add_history(session["username"], "LSB Stego Decrypt", filename)
                else:
                    flash("Tidak ditemukan pesan rahasia di dalam gambar tersebut. Pastikan itu adalah file steganografi LSB yang valid.", "warning")

            except Exception as e:
                print(f"Error saat dekripsi: {e}")
                flash(f"Terjadi error saat dekripsi/verifikasi. Pastikan file adalah file gambar steganografi LSB yang valid: {e}", "error")
    
    # Ini hanya akan tercapai jika method GET, atau jika action == 'decrypt'
    return render_template(
        "encrypt_image.html", 
        encrypt_download_file=None, # Kita tidak lagi menggunakan ini
        decrypted_message=decrypted_message
    )


@app.route("/encrypt_file", methods=["GET", "POST"])
@login_required
def encrypt_file():
    """Halaman untuk enkripsi dan dekripsi file (RSA Hybrid) - VERSI AMAN."""
    
    encrypt_download_filename = None
    
    if request.method == "POST":
        action = request.form.get("action") 
        
        # --- LOGIKA ENKRIPSI (Tidak berubah, ini sudah aman) ---
        if action == "encrypt":
            try:
                file = request.files.get("encrypt_file") 
                
                if not file or file.filename == "":
                    flash("Harap pilih file untuk enkripsi.", "error")
                    return redirect(url_for("encrypt_file"))

                file_bytes = file.read()
                
                # 1. Generate Symmetric Key (AES-256)
                session_key = get_random_bytes(32)
                
                # 2. Enkripsi File dengan Symmetric Key (AES-256 GCM)
                file_ciphertext = aes_encrypt_gcm(session_key, file_bytes)
                
                # 3. Enkripsi Symmetric Key dengan Kunci Publik RSA
                rsa_cipher = PKCS1_OAEP.new(public_rsa_key)
                encrypted_session_key = rsa_cipher.encrypt(session_key)
                
                # 4. Gabungkan (Panjang Kunci + Kunci Terenkripsi + File Terenkripsi)
                encrypted_data = len(encrypted_session_key).to_bytes(4, byteorder='big') + encrypted_session_key + file_ciphertext
                
                output_filename = f"hybrid_rsa_aes_{secure_filename(file.filename)}.bin"
                output_path = os.path.join(app.config["GENERATED_FOLDER"], output_filename)
                
                with open(output_path, "wb") as f:
                    f.write(encrypted_data)

                flash("File berhasil dienkripsi secara Hybrid (RSA-AES)!", "success")
                encrypt_download_filename = output_filename
                add_history(session["username"], "Encrypt File (RSA Hybrid)", file.filename, output_filename)

            except Exception as e:
                flash(f"Terjadi error saat enkripsi: {e}", "error")
            
            # Setelah enkripsi, render template lagi dengan link download
            return render_template(
                "encrypt_file.html", 
                encrypt_download_file=encrypt_download_filename,
                decrypt_download_file=None # Pastikan ini ada
            )
        
        # --- LOGIKA DEKRIPSI (MODIFIKASI KEAMANAN) ---
        elif action == "decrypt":
            try:
                file = request.files.get("decrypt_file") 
                
                if not file or file.filename == "":
                    flash("Harap pilih file terenkripsi sebelum menekan tombol.", "error")
                    return redirect(url_for("encrypt_file"))

                encrypted_file_bytes = file.read()
                
                # 1. Pisahkan Komponen
                key_len = int.from_bytes(encrypted_file_bytes[:4], byteorder='big')
                encrypted_session_key = encrypted_file_bytes[4:4 + key_len]
                file_ciphertext = encrypted_file_bytes[4 + key_len:]
                
                # 2. Dekripsi Symmetric Key dengan Kunci Privat RSA
                rsa_cipher = PKCS1_OAEP.new(private_rsa_key)
                session_key = rsa_cipher.decrypt(encrypted_session_key)
                
                # 3. Dekripsi File dengan Symmetric Key (AES-256 GCM)
                decrypted_data = aes_decrypt_gcm(session_key, file_ciphertext)
                
                # --- PERUBAHAN INTI ---
                # Menentukan nama file output
                original_filename = secure_filename(file.filename).replace("hybrid_rsa_aes_", "").replace(".bin", "")
                output_filename = f"decrypted_{original_filename}"
                
                # Buat file di memori, BUKAN di disk
                file_in_memory = BytesIO(decrypted_data)
                
                # Catat history
                add_history(session["username"], "Decrypt File (RSA Hybrid)", file.filename, output_filename + " (in-memory)")

                # 7. Langsung kirim file ke pengguna, JANGAN SIMPAN KE DISK
                return send_file(
                    file_in_memory,
                    download_name=output_filename,
                    as_attachment=True,
                    mimetype='application/octet-stream' # Tipe aman untuk semua file
                )
                # --- AKHIR PERUBAHAN ---

            except Exception as e:
                print(f"Error dekripsi file: {e}")
                flash(f"Terjadi error saat dekripsi. Pastikan file adalah file enkripsi Hybrid RSA-AES yang valid: {e}", "error")
                # Jika gagal, kembali ke halaman
                return redirect(url_for("encrypt_file"))

    # Jika method GET (pertama kali load halaman)
    return render_template(
        "encrypt_file.html", 
        encrypt_download_file=None,
        decrypt_download_file=None
    )
    
@app.route("/history")
@login_required
def history():
    """MODIFIED: Halaman untuk melihat riwayat enkripsi (Semua untuk Admin, Milik Sendiri untuk Member)."""
    history_db = load_data(get_history_db_path())
    
    if is_admin():
        # ADMIN: Mengumpulkan semua history dari semua user
        all_history = []
        for username, user_list in history_db.items():
            for item in user_list:
                item_copy = item.copy()
                item_copy["user"] = username # Tambahkan info user
                all_history.append(item_copy)
        user_history = all_history
        # Sorting history. Karena timestamp hanya random base64, ini akan mengurutkan secara leksikografis (sebagai upaya terbaik)
        user_history.sort(key=lambda x: x["timestamp"], reverse=True) 
        title = "Riwayat Aktivitas SEMUA Pengguna (Admin)"
    else:
        # MEMBER: Hanya melihat history-nya sendiri
        user_history = history_db.get(session["username"], [])
        user_history.reverse() 
        title = "Riwayat Aktivitas Anda"
    
    return render_template("history.html", history_list=user_history, title=title) # MODIFIED: Meneruskan 'title'

# =====================================================================
# RUTE DOWNLOAD
# =====================================================================

@app.route("/download/generated/<filename>")
@login_required
def download_generated_file(filename):
    """Rute untuk men-download file dari folder generated."""
    return send_from_directory(app.config["GENERATED_FOLDER"], filename, as_attachment=True)

# =====================================================================
# MENJALANKAN APLIKASI
# =====================================================================

if __name__ == "__main__":
    app.run(debug=True)