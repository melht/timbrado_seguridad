from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from lxml import etree
import base64

# 🚀 1️⃣ Cargar archivos CSD (Certificado y Llave)
def load_cert_key(cert_path, key_path, password_path):
    # Leer certificado .cer en formato DER
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    
    # Convertir certificado a Base64 para el XML
    cert_b64 = base64.b64encode(cert_data).decode()

    # Leer la contraseña de la clave privada
    with open(password_path, "r") as pass_file:
        password = pass_file.read().strip()

    # Leer llave privada .key en formato DER
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()

    # Convertir la clave .key a PEM y cargarla
    private_key = serialization.load_key_and_certificates(
        key_data, password.encode(), backend=default_backend()
    )

    return private_key, cert_b64

# 🚀 2️⃣ Generar la cadena original (SAT)
def generar_cadena_original(xml_path):
    # Cargar el XML CFDI
    tree = etree.parse(xml_path)
    root = tree.getroot()

    # Extraer los valores necesarios para la cadena original
    cadena_original = f"|{root.get('Version')}|{root.get('Fecha')}|{root.get('FormaPago')}|" \
                      f"{root.get('SubTotal')}|{root.get('Moneda')}|{root.get('Total')}|" \
                      f"{root.get('TipoDeComprobante')}|{root.get('MetodoPago')}|" \
                      f"{root.get('LugarExpedicion')}|"

    return cadena_original.encode()

# 🚀 3️⃣ Firmar la cadena original
def firmar_cadena(cadena_original, private_key):
    # Firmar la cadena original con SHA256
    signature = private_key.sign(
        cadena_original,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# 🚀 4️⃣ Insertar el sello y el certificado en el XML
def insertar_sello_xml(xml_path, sello, certificado):
    tree = etree.parse(xml_path)
    root = tree.getroot()

    # Agregar el sello y el certificado
    root.set("Sello", sello)
    root.set("Certificado", certificado)

    # Guardar el XML firmado
    xml_firmado = "cfdi_firmado.xml"
    tree.write(xml_firmado, pretty_print=True, xml_declaration=True, encoding="UTF-8")

    print(f"✅ XML firmado guardado como {xml_firmado}")

# 🚀 5️⃣ Ejecutar el proceso de firma
def firmar_cfdi():
    # Rutas de los archivos
    xml_path = "cfdi.xml"
    cert_path = "certificado.cer"
    key_path = "llave.key"
    password_path = "password.txt"

    # Cargar certificado y clave privada
    private_key, certificado = load_cert_key(cert_path, key_path, password_path)

    # Generar la cadena original
    cadena_original = generar_cadena_original(xml_path)

    # Firmar la cadena original
    sello = firmar_cadena(cadena_original, private_key)

    # Insertar el sello y el certificado en el XML
    insertar_sello_xml(xml_path, sello, certificado)

# Ejecutar el proceso
firmar_cfdi()
