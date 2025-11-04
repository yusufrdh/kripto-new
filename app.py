import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from PIL.PngImagePlugin import PngInfo
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

# --- Konfigurasi Flask ---
app = Flask(__name__)
# Menggunakan secret_key dari kodingan 'lama' Anda
app.secret_key = "kripto_secure_app" 
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["GENERATED_FOLDER"] = "generated"
app.config["DB_FOLDER"] = "database"  # Folder untuk menyimpan JSON

# Buat folder jika belum ada
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["GENERATED_FOLDER"], exist_ok=True)
os.makedirs(app.config["DB_FOLDER"], exist_ok=True)

# =====================================================================
# FUNGSI HELPER (Database JSON)
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
        "timestamp": base64.b64encode(get_random_bytes(6)).decode('utf-8') # Contoh timestamp unik
    })
    save_data(history_data, db_path)

# =====================================================================
# FUNGSI HELPER (Kriptografi & Steganografi)
# =====================================================================

def hash_data(data):
    """Hash password menggunakan SHA256."""
    return hashlib.sha256(data.encode()).hexdigest()

def save_key(key, filename="key.bin"):
    """Menyimpan AES key."""
    key_path = os.path.join(app.config["DB_FOLDER"], filename)
    with open(key_path, "wb") as file:
        file.write(key)

def load_key(filename="key.bin"):
    """Memuat AES key."""
    key_path = os.path.join(app.config["DB_FOLDER"], filename)
    if os.path.exists(key_path):
        with open(key_path, "rb") as file:
            return file.read()
    return None

def aes_encrypt_bytes(key, data_bytes):
    """Enkripsi data (bytes) menggunakan AES CBC."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
    # Mengembalikan IV (Initial Vector) + Ciphertext
    return cipher.iv + ciphertext

def aes_decrypt_bytes(key, ciphertext_with_iv):
    """Dekripsi data (bytes) dari AES CBC."""
    iv = ciphertext_with_iv[: AES.block_size]
    ciphertext = ciphertext_with_iv[AES.block_size :]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Mengembalikan data bytes original
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def steganography_encrypt(image_path, message, output_path):
    """Menyembunyikan pesan di metadata PNG."""
    try:
        img = Image.open(image_path)
        metadata = PngInfo()
        metadata.add_text("secret_message", message) 
        img.save(output_path, "PNG", pnginfo=metadata)
        return True
    except Exception as e:
        print(f"Error steganography_encrypt: {e}")
        return False

def steganography_decrypt(image_path):
    """Mengambil pesan dari metadata PNG."""
    try:
        img = Image.open(image_path)
        # Ganti 'message' menjadi 'secret_message' agar tidak bentrok
        message = img.text.get("secret_message")
        if message:
            return message
        return None
    except Exception as e:
        print(f"Error steganography_decrypt: {e}")
        return None

# =====================================================================
# PEMUATAN AWAL APLIKASI
# =====================================================================

# Memuat atau membuat AES key utama saat aplikasi dimulai
aes_key = load_key()
if aes_key is None:
    aes_key = get_random_bytes(16) # AES-128
    save_key(aes_key)

# =====================================================================
# DECORATOR (PENGECEK LOGIN)
# =====================================================================

def login_required(f):
    """Decorator untuk halaman yang memerlukan login."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Menggunakan 'logged_in' sesuai standar kodingan baru
        if "logged_in" not in session: 
            flash("Anda harus login untuk mengakses halaman ini.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# =====================================================================
# RUTE UTAMA (Index, Login, Register, Logout)
# =====================================================================

# app.py

# app.py

# Fungsi dekripsi helper (bisa dibuat di atas, tapi kita masukkan ke dalam index() dulu)
def decrypt_profile_data(encrypted_b64):
    """Dekripsi data Base64 terenkripsi menjadi string."""
    if not encrypted_b64:
        return None # Kembalikan None jika tidak ada data
    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        decrypted_bytes = aes_decrypt_bytes(aes_key, encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error dekripsi data: {e}")
        return None # Kembalikan None jika dekripsi gagal


@app.route("/")
def index():
    """Halaman utama / landing page."""
    
    display_name = "Pengguna" # Default
    
    if "logged_in" in session:
        username = session["username"]
        user_db = load_data(get_user_db_path())
        
        # --- START: Logika Dekripsi untuk display_name ---
        decrypted_fullname = None
        if username in user_db and user_db[username].get("fullname"):
            encrypted_fn_b64 = user_db[username]["fullname"]
            decrypted_fullname = decrypt_profile_data(encrypted_fn_b64)
        
        # Cari Fullname yang sudah didekripsi, jika tidak ada, gunakan Username
        if decrypted_fullname:
            display_name = decrypted_fullname
        else:
            display_name = username
        # --- END: Logika Dekripsi untuk display_name ---
            
        return render_template("index.html", display_name=display_name)
    
    # Biarkan seperti ini untuk menampilkan "Selamat Datang" tanpa nama jika tidak login
    return render_template("index.html", display_name=display_name)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Halaman login user (dari kodingan baru)."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user_db = load_data(get_user_db_path())
        
        if username in user_db and user_db[username]["password"] == hash_data(password):
            session["logged_in"] = True
            session["username"] = username
            flash("Login berhasil! Selamat datang.", "success")
            # UBAH: Arahkan ke index (beranda)
            return redirect(url_for("index")) 
        else:
            flash("Login gagal! Username atau password salah.", "error")
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Halaman registrasi user (dari kodingan baru)."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user_db = load_data(get_user_db_path())
        
        if username in user_db:
            flash("Username sudah terdaftar, silakan gunakan username lain.", "error")
            return redirect(url_for("register"))
            
        # Tambah user baru
        user_db[username] = {
            "password": hash_data(password)
        }
        save_data(user_db, get_user_db_path())
        
        flash("Registrasi berhasil! Silakan login.", "success")
        return redirect(url_for("login"))
        
    return render_template("register.html")

# app.py

@app.route("/logout")
@login_required
def logout():
    """Proses logout user."""
    session.clear()
    flash("Anda telah berhasil logout.", "success")
    # UBAH: Arahkan langsung ke halaman login setelah logout
    return redirect(url_for("login"))

# =====================================================================
# RUTE FITUR APLIKASI (Sesuai Gambar Anda)
# =====================================================================

# yusufrdh/kripto-new/kripto-new-27863cc49d61687d36e15b957b08e6369ae8a35a/app.py

# ... (Baris 248)
# [Rute Profil/Dashboard] - Tampilan Statis Data
@app.route("/profile") 
@login_required
def profile_dashboard():
    """Halaman dashboard profil (menampilkan data statis)."""
    
    username = session["username"]
    user_db = load_data(get_user_db_path())
    user_data = user_db.get(username, {})
    
    # === START: Tambahkan Logika Dekripsi Data Profil di Sini ===
    def decrypt_profile_data(encrypted_b64):
        """Dekripsi data Base64 terenkripsi menjadi string."""
        if not encrypted_b64:
            return "Belum Diisi"
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
            decrypted_bytes = aes_decrypt_bytes(aes_key, encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            print(f"Error dekripsi data: {e}")
            return "Data Error/Belum Diisi" # Tampilkan pesan error jika dekripsi gagal

    decrypted_fullname = decrypt_profile_data(user_data.get("fullname"))
    decrypted_email = decrypt_profile_data(user_data.get("email"))
    decrypted_phone = decrypt_profile_data(user_data.get("phone"))
    # === END: Logika Dekripsi ===
    
    # Gunakan Nama Lengkap yang didekripsi sebagai display_name
    display_name = decrypted_fullname if decrypted_fullname != "Belum Diisi" else username

    return render_template(
        "profile_dashboard.html", 
        display_name=display_name,
        # Ganti data yang dikirim ke template menjadi data yang sudah didekripsi
        fullname=decrypted_fullname,
        email=decrypted_email,
        phone=decrypted_phone
        # BARIS ASLI:
        # fullname=user_data.get("fullname", "Belum Diisi"),
        # email=user_data.get("email", "Belum Diisi"),
        # phone=user_data.get("phone", "Belum Diisi")
    )

# ... (Setelah ini baru dilanjutkan dengan @app.route("/edit_profile") dan rute lainnya)
# Modifikasi fungsi edit_profile()
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
                # 1. ENKRIPSI DATA SEBELUM DISIMPAN
                
                # Enkripsi Fullname
                fn_bytes = fullname.encode('utf-8')
                encrypted_fn = aes_encrypt_bytes(aes_key, fn_bytes)
                # Simpan sebagai Base64 String agar aman di JSON
                user_db[username]["fullname"] = base64.b64encode(encrypted_fn).decode('utf-8')
                
                # Enkripsi Email
                em_bytes = email.encode('utf-8')
                encrypted_em = aes_encrypt_bytes(aes_key, em_bytes)
                user_db[username]["email"] = base64.b64encode(encrypted_em).decode('utf-8')
                
                # Enkripsi Phone
                ph_bytes = phone.encode('utf-8')
                encrypted_ph = aes_encrypt_bytes(aes_key, ph_bytes)
                user_db[username]["phone"] = base64.b64encode(encrypted_ph).decode('utf-8')
                
                save_data(user_db, get_user_db_path())
                flash("Profil berhasil diperbarui dan dienkripsi!", "success")
            else:
                flash("Gagal memperbarui profil: Pengguna tidak ditemukan.", "error")
                
            return redirect(url_for("profile_dashboard")) 
        except Exception as e:
            flash(f"Terjadi error saat menyimpan profil: {e}", "error")
            return redirect(url_for("edit_profile"))

    # 2. DEKRIPSI DATA SAAT DIMUAT UNTUK FORM (GET)
    
    decrypted_fullname = ""
    decrypted_email = ""
    decrypted_phone = ""
    
    try:
        if user_data.get("fullname"):
            encrypted_fn_b64 = user_data["fullname"]
            encrypted_fn_bytes = base64.b64decode(encrypted_fn_b64)
            decrypted_fn_bytes = aes_decrypt_bytes(aes_key, encrypted_fn_bytes)
            decrypted_fullname = decrypted_fn_bytes.decode('utf-8')
            
        if user_data.get("email"):
            encrypted_em_b64 = user_data["email"]
            encrypted_em_bytes = base64.b64decode(encrypted_em_b64)
            decrypted_em_bytes = aes_decrypt_bytes(aes_key, encrypted_em_bytes)
            decrypted_email = decrypted_em_bytes.decode('utf-8')

        if user_data.get("phone"):
            encrypted_ph_b64 = user_data["phone"]
            encrypted_ph_bytes = base64.b64decode(encrypted_ph_b64)
            decrypted_ph_bytes = aes_decrypt_bytes(aes_key, encrypted_ph_bytes)
            decrypted_phone = decrypted_ph_bytes.decode('utf-8')
            
    except Exception as e:
        # Menangkap error dekripsi (mungkin data lama belum terenkripsi)
        print(f"Error saat dekripsi profil: {e}. Menggunakan data mentah/kosong.")
        # Jika gagal dekripsi, gunakan nilai kosong atau nilai mentah yang ada
        decrypted_fullname = user_data.get("fullname", "") if user_data.get("fullname") and len(user_data["fullname"]) < 50 else ""
        decrypted_email = user_data.get("email", "") if user_data.get("email") and len(user_data["email"]) < 50 else ""
        decrypted_phone = user_data.get("phone", "") if user_data.get("phone") and len(user_data["phone"]) < 50 else ""
        
        # Flash warning jika data lama tidak terenkripsi
        if decrypted_fullname != "" or decrypted_email != "" or decrypted_phone != "":
            flash("Data profil Anda perlu diperbarui untuk proses enkripsi. Harap Simpan Profil.", "warning")
            
            
    return render_template(
        "edit_profile.html", 
        fullname=decrypted_fullname,
        email=decrypted_email,
        phone=decrypted_phone
    )

# app.py
@app.route("/encrypt_text", methods=["GET", "POST"])
@login_required
def encrypt_text():
    """Halaman untuk enkripsi dan dekripsi teks."""
    result_text = None
    action_type = None
    input_text = ""

    if request.method == "POST":
        try:
            # Mengambil input teks dan aksi (encrypt/decrypt) dari form
            input_text = request.form["text_input"]
            action = request.form.get("action") 

            if action == "encrypt":
                # --- LOGIKA ENKRIPSI ---
                text_bytes = input_text.encode('utf-8')
                encrypted_data = aes_encrypt_bytes(aes_key, text_bytes)
                result_text = encrypted_data.hex() # Hasil dalam bentuk Hex String
                action_type = "Enkripsi"
                
                flash("Teks berhasil dienkripsi!", "success")
                add_history(session["username"], "Encrypt Text", input_text[:30]+"...")
                
            elif action == "decrypt":
                # --- LOGIKA DEKRIPSI ---
                # Input adalah string hex, konversi ke bytes
                encrypted_data = bytes.fromhex(input_text)
                decrypted_bytes = aes_decrypt_bytes(aes_key, encrypted_data)
                result_text = decrypted_bytes.decode('utf-8') # Hasil dekripsi (Plaintext)
                action_type = "Dekripsi"
                
                flash("Teks berhasil didekripsi!", "success")
                add_history(session["username"], "Decrypt Text", input_text[:30]+"...")
            else:
                raise ValueError("Aksi tidak valid.")

        except Exception as e:
            flash(f"Terjadi error saat {action_type.lower() if action_type else 'pemrosesan'}: Pastikan input sudah benar (teks biasa untuk enkripsi, heksadesimal untuk dekripsi). Error: {e}", "error")
            result_text = None
            
    # Mengirimkan input_text (untuk mempertahankan nilai di textarea) dan result_text ke template
    return render_template("encrypt_text.html", result_text=result_text, input_text=input_text)

@app.route("/encrypt_image", methods=["GET", "POST"])
@login_required
def encrypt_image():
    """Halaman untuk steganografi gambar (logika penuh)."""
    download_filename = None
    if request.method == "POST":
        try:
            # 1. Cek file dan pesan
            if "image" not in request.files or "message" not in request.form:
                flash("Harap masukkan file gambar dan pesan rahasia.", "error")
                return redirect(request.url)
                
            file = request.files["image"]
            message = request.form["message"]
            
            if file.filename == "" or message == "":
                flash("File atau pesan tidak boleh kosong.", "error")
                return redirect(request.url)
                
            # 2. Simpan file upload
            filename = secure_filename(file.filename)
            input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(input_path)
            
            # 3. Proses Steganografi
            output_filename = f"stego_{filename}.png" # Pastikan output PNG
            output_path = os.path.join(app.config["GENERATED_FOLDER"], output_filename)
            
            if not steganography_encrypt(input_path, message, output_path):
                raise Exception("Gagal melakukan steganografi.")
                
            flash("Pesan berhasil disembunyikan ke dalam gambar!", "success")
            download_filename = output_filename
            
            # 4. Simpan ke history
            add_history(session["username"], "Steganography Encrypt", filename, output_filename)

        except Exception as e:
            flash(f"Terjadi error: {e}", "error")
            
    return render_template("encrypt_image.html", download_file=download_filename)


@app.route("/encrypt_file", methods=["GET", "POST"])
@login_required
def encrypt_file():
    """Halaman untuk enkripsi file (logika penuh)."""
    download_filename = None
    if request.method == "POST":
        try:
            if "file" not in request.files:
                flash("Harap masukkan file.", "error")
                return redirect(request.url)
                
            file = request.files["file"]
            if file.filename == "":
                flash("File tidak boleh kosong.", "error")
                return redirect(request.url)

            # 1. Baca file sebagai bytes
            file_bytes = file.read()
            
            # 2. Enkripsi bytes
            encrypted_data = aes_encrypt_bytes(aes_key, file_bytes)
            
            # 3. Siapkan file untuk di-download
            output_filename = f"encrypted_{secure_filename(file.filename)}.bin"
            output_path = os.path.join(app.config["GENERATED_FOLDER"], output_filename)
            
            with open(output_path, "wb") as f:
                f.write(encrypted_data)

            flash("File berhasil dienkripsi!", "success")
            download_filename = output_filename
            
            # 4. Simpan ke history
            add_history(session["username"], "Encrypt File", file.filename, output_filename)

        except Exception as e:
            flash(f"Terjadi error: {e}", "error")

    return render_template("encrypt_file.html", download_file=download_filename)


@app.route("/history")
@login_required
def history():
    """Halaman untuk melihat riwayat enkripsi."""
    history_db = load_data(get_history_db_path())
    user_history = history_db.get(session["username"], [])
    # Membalik list agar yang terbaru di atas
    user_history.reverse() 
    
    return render_template("history.html", history_list=user_history)

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