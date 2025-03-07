#importamos las librerias 
import os                       # Para manejar rutas de archivos
from cryptography import x509    # Para manejar certificados X.509
import base64                    # Para codificar y decodificar en Base64
from cryptography.hazmat.primitives import serialization   # Para manejar claves criptográficas
from cryptography.hazmat.backends import default_backend    # Backend criptográfico
from cryptography.hazmat.primitives.asymmetric import padding   # Para aplicar padding en firmas
from cryptography.hazmat.primitives import hashes  #Para aplicar funciones hash


# Ruta del archivo de clave privada 
key_path = "CAÑF770131PA3_20230509114635\Claveprivada_FIEL_CAÑF770131PA3_20230509_114635.key"

#creamos la variable de la llave privada
password = "12345678a".encode("utf-8")
# Leemos  la llave privada 
with open(key_path, "rb") as key_file:
    key_data = key_file.read()

#intentamos carcar la llave privada utilizando la contraseña
try:
    private_key = serialization.load_der_private_key(
        key_data, password=password, backend=default_backend()
    )
    print("Llave privada cargada correctamente.")
except ValueError as e:
    print("Error: No se pudo cargar la llave privada. Verifica la contraseña.")
    print(str(e))



# Ruta de la carpeta donde están los archivos
base_path = "CAÑF770131PA3_20230509114635"

# Rutas de los archivos
cert_path = os.path.join(base_path, "Claveprivada_FIEL_CAÑF770131PA3_20230509_114635.cer")

def obtener_serie_certificado(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()

    # Cargar el certificado
    cert = x509.load_der_x509_certificate(cert_data)

    # Extraer el número de serie en formato hexadecimal
    serie_cert = format(cert.serial_number, 'X').zfill(20)

    return serie_cert, base64.b64encode(cert_data).decode()

# Obtener serie y certificado en Base64
serie_certificado, cert_base64 = obtener_serie_certificado(cert_path)

print(" Número de serie del certificado:", serie_certificado)
print(" Certificado en Base64:", cert_base64[:50] + "...")  # Muestra solo parte del Base64


import lxml.etree as ET

def generar_cadena_original(xml_path, xslt_path):
    # Cargar el XML CFDI
    xml_tree = ET.parse(xml_path)
    
    # Cargar la hoja de estilo XSLT del SAT
    xslt_tree = ET.parse(xslt_path)
    transform = ET.XSLT(xslt_tree)
    
    # Aplicar la transformación para obtener la cadena original
    cadena_original = str(transform(xml_tree))
    return cadena_original.strip()

# Rutas del XML y la hoja de estilo XSLT 
xml_path = "cfdi.xml"
xslt_path = "cadenaoriginal_4_0.xslt"

# Generar la cadena original a partir del XML y la hoja de estilo XSLT
cadena_original = generar_cadena_original(xml_path, xslt_path)
print("Cadena original generada:", cadena_original)


# Función para firmar la cadena original usando la llave privada
def firmar_cadena(private_key, cadena_original):
    firma = private_key.sign(
        cadena_original.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(firma).decode()

# Generamos la firma digital de la cadena original
firma_digital = firmar_cadena(private_key, cadena_original)
print("Firma digital generada:", firma_digital)

# Función para insertar la firma y el certificado en el XML del CFDI
def insertar_firma_en_xml(xml_path, firma, certificado):
    # Cargar XML
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Agregar los atributos requeridos
    root.set("Sello", firma)
    root.set("Certificado", certificado)

    # Guardar el XML firmado
    tree.write("cfdi_firmado.xml", encoding="utf-8", xml_declaration=True)

# Insertar la firma y el certificado en el XML
insertar_firma_en_xml(xml_path, firma_digital, cert_base64)
print("CFDI firmado guardado como 'cfdi_firmado.xml'")
