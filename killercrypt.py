import base64
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Importación faltante
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import numpy as np

# PARÁMETROS DE SEGURIDAD
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32
SALT_SIZE = 32
PBKDF2_ITERATIONS = 600_000
HKDF_INFO = b"killer-secure-system"

# Paleta de colores moderna
COLORS = {
    "primary": "#1a237e",
    "secondary": "#4a148c",
    "accent": "#00b0ff",
    "background": "#f5f5f5",
    "text": "#263238",
    "success": "#00c853",
    "warning": "#ff9100",
    "card": "#ffffff",
    "border": "#cfd8dc",
    "dark_accent": "#0d47a1"
}

# Generación y gestión de claves RSA
def generar_par_claves():
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def serializar_clave_publica(clave_publica):
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserializar_clave_publica(datos):
    return serialization.load_pem_public_key(datos, backend=default_backend())

def serializar_clave_privada(clave_privada, password):
    return clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

def deserializar_clave_privada(datos, password):
    return serialization.load_pem_private_key(
        datos,
        password=password.encode(),
        backend=default_backend()
    )

# Funciones de derivación de claves
def derivar_clave_maestra(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=64,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def derivar_subclaves(clave_maestra: bytes) -> tuple:
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=64,
        salt=None,
        info=HKDF_INFO,
        backend=default_backend()
    )
    clave_expandida = hkdf.derive(clave_maestra)
    return (
        clave_expandida[:32],   # Clave AES
        clave_expandida[32:48], # Clave HMAC
        clave_expandida[48:]    # Clave adicional
    )

# Funciones de cifrado/descifrado
def cifrado_aes(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(data) + encryptor.finalize()
    return nonce + cifrado + encryptor.tag

def descifrado_aes(data: bytes, key: bytes) -> bytes:
    nonce = data[:16]
    cifrado = data[16:-16]
    tag = data[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cifrado) + decryptor.finalize()

def calcular_hmac(data: bytes, key: bytes) -> bytes:
    h = hmac.new(key, data, hashlib.sha3_256)
    return h.digest()

# Funciones de cifrado/descifrado mejoradas
def cifrar(texto, password, clave_publica):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(16)
    
    clave_maestra = derivar_clave_maestra(password, salt)
    clave_aes, clave_hmac, _ = derivar_subclaves(clave_maestra)
    
    datos = texto.encode()
    cifrado = cifrado_aes(datos, clave_aes, nonce)
    
    hmac_digest = calcular_hmac(cifrado, clave_hmac)
    
    clave_maestra_cifrada = clave_publica.encrypt(
        clave_maestra,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    paquete = (
        len(clave_maestra_cifrada).to_bytes(4, 'big') +
        clave_maestra_cifrada +
        salt +
        hmac_digest +
        cifrado
    )
    
    return base64.b85encode(paquete).decode()

def descifrar(texto_codificado, password, clave_privada):
    paquete = base64.b85decode(texto_codificado)
    
    len_size = 4
    hmac_size = 32  # SHA3-256
    
    key_len = int.from_bytes(paquete[:len_size], 'big')
    clave_maestra_cifrada = paquete[len_size:len_size+key_len]
    salt = paquete[len_size+key_len:len_size+key_len+SALT_SIZE]
    hmac_digest = paquete[len_size+key_len+SALT_SIZE:len_size+key_len+SALT_SIZE+hmac_size]
    cifrado = paquete[len_size+key_len+SALT_SIZE+hmac_size:]
    
    clave_maestra = clave_privada.decrypt(
        clave_maestra_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    clave_aes, clave_hmac, _ = derivar_subclaves(clave_maestra)
    
    hmac_calculado = calcular_hmac(cifrado, clave_hmac)
    if hmac_digest != hmac_calculado:
        raise ValueError("Fallo de autenticación: posible manipulación de datos")
    
    datos = descifrado_aes(cifrado, clave_aes)
    return datos.decode()

# Interfaz gráfica moderna
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("KillerCrypt - Secure Encryption")
        self.geometry("800x600")
        self.configure(bg=COLORS["background"])
        self.resizable(True, True)
        
        # Cargar claves
        self.clave_privada, self.clave_publica = self.cargar_claves()
        
        # Configurar estilo
        self.setup_styles()
        
        # Crear widgets
        self.create_widgets()
        
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configurar estilos
        self.style.configure('TFrame', background=COLORS["background"])
        self.style.configure('TLabel', background=COLORS["background"], foreground=COLORS["text"], font=("Segoe UI", 10))
        self.style.configure('TButton', font=("Segoe UI", 10, "bold"), borderwidth=1)
        self.style.configure('Header.TLabel', font=("Segoe UI", 16, "bold"), foreground=COLORS["primary"])
        self.style.configure('Card.TFrame', background=COLORS["card"], relief="solid", borderwidth=1, bordercolor=COLORS["border"])
        self.style.configure('Primary.TButton', background=COLORS["primary"], foreground="white")
        self.style.configure('Accent.TButton', background=COLORS["accent"], foreground="white")
        
        # Mapear colores de botones
        self.style.map('Primary.TButton',
            background=[('active', COLORS["secondary"]), ('pressed', COLORS["primary"])]
        )
    
    def cargar_claves(self):
        try:
            with open("private_key.pem", "rb") as f:
                privada = deserializar_clave_privada(f.read(), "secure_master_key")
            with open("public_key.pem", "rb") as f:
                publica = deserializar_clave_publica(f.read())
            return privada, publica
        except Exception as e:
            print(f"Generando nuevas claves: {e}")
            privada, publica = generar_par_claves()
            with open("private_key.pem", "wb") as f:
                f.write(serializar_clave_privada(privada, "secure_master_key"))
            with open("public_key.pem", "wb") as f:
                f.write(serializar_clave_publica(publica))
            return privada, publica
    
    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Encabezado
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(header_frame, text="KillerCrypt", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Tarjeta de entrada
        input_card = ttk.Frame(main_frame, style='Card.TFrame', padding=15)
        input_card.pack(fill=tk.BOTH, pady=10)
        
        ttk.Label(input_card, text="Texto:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        self.input_text = scrolledtext.ScrolledText(
            input_card, 
            height=8, 
            font=("Consolas", 10),
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )
        self.input_text.pack(fill=tk.X, pady=5)
        
        # Tarjeta de contraseña
        password_card = ttk.Frame(main_frame, style='Card.TFrame', padding=15)
        password_card.pack(fill=tk.X, pady=10)
        
        ttk.Label(password_card, text="Contraseña:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        self.password_entry = ttk.Entry(
            password_card, 
            show="*", 
            font=("Segoe UI", 10),
            width=40
        )
        self.password_entry.pack(fill=tk.X, pady=5)
        
        # Botones de acción
        btn_frame = ttk.Frame(password_card)
        btn_frame.pack(fill=tk.X, pady=10)
        
        encrypt_btn = ttk.Button(
            btn_frame, 
            text="CIFRAR", 
            style='Primary.TButton',
            command=lambda: self.procesar("cifrar")
        )
        encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        decrypt_btn = ttk.Button(
            btn_frame, 
            text="DESCIFRAR", 
            style='Primary.TButton',
            command=lambda: self.procesar("descifrar")
        )
        decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        # Tarjeta de resultado
        result_card = ttk.Frame(main_frame, style='Card.TFrame', padding=15)
        result_card.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(result_card, text="Resultado:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        self.result_text = scrolledtext.ScrolledText(
            result_card, 
            height=8, 
            font=("Consolas", 10),
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            state=tk.DISABLED
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Botón copiar
        copy_btn = ttk.Button(
            result_card, 
            text="Copiar Resultado", 
            style='Accent.TButton',
            command=self.copiar_resultado
        )
        copy_btn.pack(pady=10)
        
        # Panel de seguridad
        security_frame = ttk.Frame(main_frame, style='Card.TFrame', padding=15)
        security_frame.pack(fill=tk.X, pady=10)
        
        security_text = (
            "🔒 Sistema de Cifrado Seguro\n"
            "• RSA-4096 con OAEP/SHA-256\n"
            "• AES-256-GCM\n"
            "• HMAC-SHA3-256 para autenticación"
        )
        
        security_label = ttk.Label(
            security_frame, 
            text=security_text,
            justify=tk.LEFT,
            font=("Segoe UI", 9)
        )
        security_label.pack(anchor=tk.W)
    
    def procesar(self, opcion):
        input_text = self.input_text.get("1.0", tk.END).strip()
        password = self.password_entry.get()
        
        if not input_text:
            messagebox.showwarning("Entrada vacía", "Por favor, ingresa texto para procesar", parent=self)
            return
        if not password:
            messagebox.showwarning("Contraseña requerida", "Debes ingresar una contraseña de seguridad", parent=self)
            return
            
        try:
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete("1.0", tk.END)
            
            if opcion == "cifrar":
                resultado = cifrar(input_text, password, self.clave_publica)
            else:
                resultado = descifrar(input_text, password, self.clave_privada)
                
            self.result_text.insert(tk.END, resultado)
            
        except Exception as e:
            messagebox.showerror(
                "Error", 
                f"Error durante el proceso:\n{str(e)}", 
                parent=self
            )
            self.result_text.insert(tk.END, f"Error: {str(e)}")
        finally:
            self.result_text.config(state=tk.NORMAL)
    
    def copiar_resultado(self):
        resultado = self.result_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(resultado)
        messagebox.showinfo("Copiado", "Resultado copiado al portapapeles", parent=self)

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()