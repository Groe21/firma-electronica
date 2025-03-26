import hashlib
import fitz  # PyMuPDF
import qrcode
from datetime import datetime
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

class PDFSigner:
    def __init__(self, pdf_path, p12_path, p12_password):
        self.pdf_path = pdf_path
        self.p12_path = p12_path
        self.p12_password = p12_password
        self.signer_name = self.get_certificate_owner()

    def get_certificate_owner(self):
        """Extract certificate owner information from P12"""
        with open(self.p12_path, 'rb') as p12_file:
            private_key, certificate, _ = pkcs12.load_key_and_certificates(
                p12_file.read(),
                self.p12_password.encode()
            )
        subject = certificate.subject
        for attr in subject:
            if attr.oid._name == 'commonName':
                return attr.value
        return None

    def get_pdf_hash(self):
        """Generate SHA-256 hash of PDF content"""
        hasher = hashlib.sha256()
        with open(self.pdf_path, 'rb') as pdf:
            hasher.update(pdf.read())
        return hasher.digest()

    def sign_hash(self, hash_value):
        """Sign the hash using P12 certificate"""
        with open(self.p12_path, 'rb') as p12_file:
            private_key, certificate, _ = pkcs12.load_key_and_certificates(
                p12_file.read(),
                self.p12_password.encode()
            )
        
        signature = private_key.sign(
            hash_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def generate_qr(self, signature_data, qr_path):
        """Generate QR code from signature"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(signature_data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(qr_path)
        return qr_path

    def insert_signature(self, output_path, qr_path, position=None):
        """Insert signature and QR into PDF"""
        doc = fitz.open(self.pdf_path)
        page = doc[-1]  # Last page

        # Default position or custom
        if position is None:
            qr_x = page.rect.width - 150
            qr_y = page.rect.height - 150
            sig_x, sig_y = 50, page.rect.height - 150
        else:
            qr_x, qr_y = position['qr']
            sig_x, sig_y = position['signature']

        # Add signature text with certificate owner name
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        signature_text = (
            f"Firmado digitalmente por: {self.signer_name}\n"
            f"Fecha: {timestamp}\n"
            "Este documento ha sido firmado electrónicamente"
        )
        page.insert_text((sig_x, sig_y), signature_text, fontsize=10)

        # Insert QR code
        rect = fitz.Rect(qr_x, qr_y, qr_x + 100, qr_y + 100)
        page.insert_image(rect, filename=qr_path)

        doc.save(output_path)
        doc.close()
        return True

def sign_document(pdf_path, p12_path, p12_password, output_path, position=None):
    try:
        signer = PDFSigner(pdf_path, p12_path, p12_password)
        
        # Step 1: Generate hash
        pdf_hash = signer.get_pdf_hash()
        
        # Step 2: Sign hash
        signature = signer.sign_hash(pdf_hash)
        
        # Step 3: Generate QR
        qr_path = "temp_qr.png"
        signer.generate_qr(signature, qr_path)
        
        # Step 4: Insert signature and QR
        success = signer.insert_signature(output_path, qr_path, position)
        
        if success:
            print(f"✅ Document signed successfully: {output_path}")
            return True
    except Exception as e:
        print(f"❌ Error signing document: {e}")
        return False

# Example usage
if __name__ == "__main__":
    pdf_file = "Doc1.pdf"
    p12_file = "firma.p12"
    p12_password = "Mathias19"
    output_pdf = "documento_firmado.pdf"
    
    # Optional: Custom position
    custom_position = {
        'qr': (400, 500),
        'signature': (50, 500)
    }
    
    sign_document(pdf_file, p12_file, p12_password, output_pdf)