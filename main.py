import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta, timezone

ca_private_key = None
ca_certificate = None

def saveCA():
    try:
        with open("ca_key.pem", "wb") as f:
            f.write(ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("ca_cert.pem", "wb") as f:
            f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

        print("\nCA guardada en disco (ca_key.pem, ca_cert.pem).\n")
    except Exception as e:
        print(f"\nERROR al guardar la CA: {e}\n")

def loadCA():
    global ca_private_key, ca_certificate
    try:
        with open("ca_key.pem", "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open("ca_cert.pem", "rb") as f:
            ca_certificate = x509.load_pem_x509_certificate(f.read())

        print("\nCA cargada correctamente desde disco.\n")
    except Exception as e:
        print(f"\nERROR al cargar la CA: {e}\n")

def generateCACertificate():
    global ca_private_key, ca_certificate
    common_name = input("Introduce el Common Name para la CA: ")

    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    ca_certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        ca_private_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(ca_private_key, hashes.SHA256())

    print("\nCA generada correctamente. Certificado:\n")
    print(ca_certificate.public_bytes(serialization.Encoding.PEM).decode())

    saveCA()

def generateCSR():
    common_name = input("Common Name: ")
    country = input("Country (2 letras): ") or "ES"
    state = input("State: ") or "State"
    locality = input("Locality: ") or "City"
    organization = input("Organization: ") or "Org"

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    private_key_filename = f"private_key_{timestamp}.pem"
    csr_filename = f"request_{timestamp}.csr"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

    try:
        with open(private_key_filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(csr_filename, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        print(f"\nCSR generado correctamente: '{csr_filename}'\nClave privada guardada en: '{private_key_filename}'\n")
    except Exception as e:
        print(f"\nERROR al guardar archivos del CSR: {e}\n")

def issueCertificate():
    global ca_private_key, ca_certificate
    if not ca_certificate or not ca_private_key:
        print("WARNING: Primero debes generar o cargar una CA (opciones 1 o 2).\n")
        return

    csr_path = input("Ruta del archivo CSR (por defecto 'request.csr'): ") or "request.csr"

    if not os.path.exists(csr_path):
        print(f"ERROR: No se encuentra el archivo '{csr_path}'. Primero genera un CSR.\n")
        return

    try:
        with open(csr_path, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
    except Exception as e:
        print(f"ERROR al leer el CSR: {e}\n")
        return

    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=90)
    ).sign(ca_private_key, hashes.SHA256())

    try:
        with open("signed_certificate.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("\nCertificado firmado correctamente y guardado en: 'signed_certificate.pem'\n")
    except Exception as e:
        print(f"\nERROR al guardar el certificado: {e}\n")

def validateCertificate():
    global ca_certificate
    if not ca_certificate:
        print("WARNING: Debes generar o cargar primero la CA para poder validar.\n")
        return

    cert_path = input("Ruta del certificado a validar (por defecto 'signed_certificate.pem'): ") or "signed_certificate.pem"

    if not os.path.exists(cert_path):
        print(f"ERROR: No se encuentra el archivo '{cert_path}'.\n")
        return

    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        ca_certificate.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        print("\nEl certificado es válido y fue firmado por esta CA.\n")
    except Exception as e:
        print(f"\nERROR: El certificado no es válido o no fue firmado por esta CA.\n{str(e)}\n")

def menu():
    while True:
        print("\n--- MENÚ ---")
        print("[1] - Generar entidad CA")
        print("[2] - Cargar CA desde disco")
        print("[3] - Generar CSR")
        print("[4] - Emitir certificado")
        print("[5] - Validar certificado")
        print("[0] - Salir")

        option = input("\nElige una opción: ")

        if option == "1":
            generateCACertificate()
        elif option == "2":
            loadCA()
        elif option == "3":
            generateCSR()
        elif option == "4":
            issueCertificate()
        elif option == "5":
            validateCertificate()
        elif option == "0":
            print("Saliendo...")
            break
        else:
            print("Opción no válida, intenta de nuevo.")

if __name__ == "__main__":
    menu()