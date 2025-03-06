# Ejercicio de timbrado
# Seguridad informática y análisis forense
# Mel, Leo, Juan y Santi

import xml.etree.ElementTree as ET
from pycfdi.cfdv40 import CFDI
from pycfdi.sat import validar_certificado
from cryptography.hazmat.primitives.serialization import load_der_private_key
from lxml import etree
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64



# 3. Usar cryptography o OpenSSL en Python para firmar el CFDI con el archivo .cer y .key.



def convertir_cer_a_pem(cer_path, output_pem):
    with open(cer_path, "rb") as cer_file:
        contenido = cer_file.read()
        certificado_b64 = base64.b64encode(contenido).decode()

    with open(output_pem, "w") as pem_file:
        pem_file.write("-----BEGIN CERTIFICATE-----\n")
        pem_file.write("\n".join(certificado_b64[i:i+64] for i in range(0, len(certificado_b64), 64)))
        pem_file.write("\n-----END CERTIFICATE-----\n")

convertir_cer_a_pem("certificado.cer", "certificado.pem")
print("✅ Certificado convertido a PEM.")

def convertir_key_a_pem(key_path, password, output_pem):
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()
    
    private_key = load_der_private_key(key_data, password.encode())

    with open(output_pem, "wb") as pem_file:
        pem_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

convertir_key_a_pem("clave.key", "TUPASSWORD", "clave.pem")
print("✅ Clave privada convertida a PEM.")

def obtener_cadena_original(xml_path, xslt_path):
    xml_doc = etree.parse(xml_path)
    xslt_doc = etree.parse(xslt_path)
    transform = etree.XSLT(xslt_doc)
    return str(transform(xml_doc)).strip()

xml_file = "factura.xml"
xslt_file = "cadenaoriginal_4_0.xslt"  # Descárgalo del SAT

cadena_original = obtener_cadena_original(xml_file, xslt_file)
print("Cadena Original:", cadena_original)


def firmar_cadena_original(cadena, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Ya no tiene contraseña después de convertirla a PEM
        )

    firma = private_key.sign(
        cadena.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(firma).decode()

private_key_file = "clave.pem"
firma = firmar_cadena_original(cadena_original, private_key_file)
print("Firma:", firma)

import xml.etree.ElementTree as ET

def insertar_firma_en_xml(xml_path, firma):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    # Agregar el atributo "Sello"
    root.set("Sello", firma)

    tree.write("factura_firmada.xml", encoding="utf-8", xml_declaration=True)

insertar_firma_en_xml(xml_file, firma)
print("XML firmado correctamente.")


cfdi = CFDI.parse("factura_firmada.xml")
resultado = validar_certificado(cfdi.certificado)

if resultado:
    print("Certificado válido")
else:
    print("Certificado inválido")
