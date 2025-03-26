import PyPDF2
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from datetime import datetime
from endesive import pdf
import os

def firmar_pdf(pdf_file, p12_file, password):
    # Cargar el certificado digital (.p12)
    with open(p12_file, "rb") as cert_file:
        p12_data = cert_file.read()
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(p12_data, password.encode())

    if private_key is None or cert is None:
        print("❌ Error: El archivo P12 no contiene la clave privada o el certificado.")
        return

    firmante = cert.subject.rfc4514_string()
    fecha_firma = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    # Configuración de la firma digital
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "sigbutton": True,
        "sigfield": "Signature1",  # Se debe verificar que el PDF tenga este campo
        "auto_sigfield": True,     # Crea el campo si no existe
        "sigandcertify": True,     # Certifica el documento después de la firma
        "signaturebox": (100, 100, 300, 200),  # Ubicación de la firma
        "signature": "Documento firmado digitalmente",
        "contact": firmante,
        "location": "Ecuador",
        "signingdate": fecha_firma,
        "reason": "Firma electrónica válida",
        "password": password,
        "tsa": "http://timestamp.digicert.com"  # Servidor de marca de tiempo
    }

    # Leer el PDF original
    with open(pdf_file, "rb") as f:
        datau = f.read()

    # Firmar el PDF
    datas = pdf.cms.sign(datau, dct, private_key, cert, additional_certs, "sha256")

    # Guardar el PDF firmado
    signed_pdf = "documento_firmado.pdf"
    with open(signed_pdf, "wb") as output_pdf:
        output_pdf.write(datas)

    print(f"✅ Documento firmado correctamente: {signed_pdf}")

# Rutas de los archivos
pdf_file = "Doc1.pdf"  # Asegúrate de que contenga un campo de firma
p12_file = "firma.p12"  # Tu archivo de firma digital
password = "Mathias19"  # Reemplaza con la contraseña correcta

if os.path.exists(pdf_file) and os.path.exists(p12_file):
    firmar_pdf(pdf_file, p12_file, password)
else:
    print("❌ Error: No se encontraron los archivos PDF o P12.")
