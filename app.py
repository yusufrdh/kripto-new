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

@app.route("/")
def index():
    """Halaman utama / landing page."""
    # Jika Anda ingin halaman utama langsung ke profil jika sudah login:
    if "logged_in" in session:
        return redirect(url_for("profile"))
    return render_template("index.html")

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
            return redirect(url_for("profile")) # Arahkan ke profile
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

@app.route("/logout")
@login_required
def logout():
    """Proses logout user."""
    session.clear()
    flash("Anda telah berhasil logout.", "success")
    return redirect(url_for("index"))

# =====================================================================
# RUTE FITUR APLIKASI (Sesuai Gambar Anda)
# =====================================================================

@app.route("/profile")
@login_required
def profile():
    """Halaman profile pengguna (dashboard)."""
    return render_template("profile.html", username=session["username"])

@app.route("/encrypt_text", methods=["GET", "POST"])
@login_required
def encrypt_text():
    """Halaman untuk enkripsi teks (logika penuh)."""
    encrypted_text_hex = None
    if request.method == "POST":
        try:
            text_to_encrypt = request.form["text_input"]
            text_bytes = text_to_encrypt.encode('utf-8')
            
            # Enkripsi menggunakan AES key global
            encrypted_data = aes_encrypt_bytes(aes_key, text_bytes)
            encrypted_text_hex = encrypted_data.hex()
            
            flash("Teks berhasil dienkripsi!", "success")
            # Simpan ke history
            add_history(session["username"], "Encrypt Text", text_to_encrypt[:30]+"...")

        except Exception as e:
            flash(f"Terjadi error saat enkripsi: {e}", "error")
            
    return render_template("encrypt_text.html", encrypted_result=encrypted_text_hex)

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