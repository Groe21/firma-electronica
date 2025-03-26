import hashlib
import fitz  # PyMuPDF
import OpenSSL.crypto as crypto
from datetime import datetime
import qrcode

def get_pdf_hash(pdf_path):
    """Genera un hash SHA-256 del contenido de un PDF."""
    hasher = hashlib.sha256()
    with open(pdf_path, 'rb') as pdf:
        hasher.update(pdf.read())
    return hasher.digest()

def get_certificate_info(p12_path, p12_password):
    """Obtiene la información del certificado P12."""
    with open(p12_path, 'rb') as p12_file:
        p12 = crypto.load_pkcs12(p12_file.read(), p12_password.encode())
    cert = p12.get_certificate()
    subject = cert.get_subject()
    return {
        'nombre': subject.CN,
        'razon': 'Firma Digital',
        'localizacion': subject.C if hasattr(subject, 'C') else 'EC'
    }

def sign_hash(hash_value, p12_path, p12_password):
    """Firma el hash usando la clave privada del certificado P12."""
    with open(p12_path, 'rb') as p12_file:
        p12 = crypto.load_pkcs12(p12_file.read(), p12_password.encode())
    private_key = p12.get_privatekey()
    signature = crypto.sign(private_key, hash_value, 'sha256')
    return signature

def generate_qr(signature_data):
    """Genera el código QR con la firma."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(signature_data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white")

def insert_signature_in_pdf(pdf_path, output_path, signature_text, cert_info, position=(100, 100)):
    """Inserta la firma en el PDF visualmente en una posición específica."""
    doc = fitz.open(pdf_path)
    page = doc[-1]  # Última página
    
    # Generar QR
    qr_img = generate_qr(signature_text)
    qr_img.save("temp_qr.png")
    
    # Insertar QR
    rect = fitz.Rect(position[0], position[1], position[0] + 100, position[1] + 100)
    page.insert_image(rect, filename="temp_qr.png")
    
    # Configuración de la firma visual
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "-05:00"
    signature_display = (
        f"FIRMADO POR: {cert_info['nombre']}\n"
        f"RAZON: {cert_info['razon']}\n"
        f"LOCALIZACION: {cert_info['localizacion']}\n"
        f"FECHA: {timestamp}\n"
        f"VALIDAR CON: www.firmadigital.gob.ec 3.1.2"
    )
    
    # Insertar texto de firma
    page.insert_text((position[0], position[1] + 120), 
                    signature_display, 
                    fontsize=8, 
                    color=(0, 0, 0))  # Negro

    doc.save(output_path)
    print(f"✅ Firma insertada en {output_path}")

# --- Prueba ---
pdf_file = "Doc1.pdf"
p12_file = "firma.p12"
p12_password = "Mathias19"

# Obtener hash y firma
pdf_hash = get_pdf_hash(pdf_file)
signature = sign_hash(pdf_hash, p12_file, p12_password)
cert_info = get_certificate_info(p12_file, p12_password)

# Insertar firma con QR
insert_signature_in_pdf(
    pdf_file, 
    "documento_firmado.pdf", 
    signature.hex(), 
    cert_info,
    position=(400, 50)
)
