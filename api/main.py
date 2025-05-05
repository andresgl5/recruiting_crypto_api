from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from pydantic import BaseModel
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta, timezone
import uvicorn
import os
import json

app = FastAPI()
CERT_DIR = "certs"
os.makedirs(CERT_DIR, exist_ok=True)

with open('./config.json') as f:
    config = json.load(f)
API_KEY = config['api_key']

ca_private_key = None
ca_certificate = None

# -----------------------
# Autenticación por API KEY
# -----------------------
def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

# -----------------------
# Modelos
# -----------------------
class CommonNameRequest(BaseModel):
    common_name: str

class CSRRequest(BaseModel):
    csr: str

class CertificateRequest(BaseModel):
    crt: str

class CSRGenerateRequest(BaseModel):
    common_name: str
    country: str = "ES"
    state: str = "State"
    locality: str = "City"
    organization: str = "Org"

# -----------------------
# Endpoints
# -----------------------

@app.post("/crypto/ca")
async def generate_ca(body: CommonNameRequest, _: str = Depends(verify_api_key)):
    global ca_private_key, ca_certificate

    common_name = body.common_name
    
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

    with open(os.path.join(CERT_DIR, "ca.key"), "w") as f:
        json.dump({"type": "ca_key", "content": ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()}, f, indent=2)

    with open(os.path.join(CERT_DIR, "ca.crt"), "w") as f:
        json.dump({"type": "ca_cert", "content": ca_certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode()}, f, indent=2)

    return {
        "crt": ca_certificate.public_bytes(serialization.Encoding.PEM).decode()
    }

@app.post("/crypto/csr")
async def generate_csr(body: CSRGenerateRequest, _: str = Depends(verify_api_key)):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, body.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, body.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, body.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, body.organization),
        x509.NameAttribute(NameOID.COMMON_NAME, body.common_name),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(os.path.join(CERT_DIR, f"key_{body.common_name}.key"), "w") as f:
        json.dump({"type": "private_key", "content": private_key_pem.decode()}, f, indent=2)

    with open(os.path.join(CERT_DIR, f"csr_{body.common_name}.csr"), "w") as f:
        json.dump({"type": "csr", "content": csr_pem.decode()}, f, indent=2)

    return {
        # "private_key": private_key_pem.decode(),
        "csr": csr_pem.decode()
    }

@app.post("/crypto/crt")
async def issue_certificate(body: CSRRequest, _: str = Depends(verify_api_key)):
    global ca_private_key, ca_certificate
    if not ca_private_key or not ca_certificate:
        raise HTTPException(status_code=400, detail="CA not initialized")

    try:
        csr = x509.load_pem_x509_csr(body.csr.encode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CSR: {str(e)}")

    common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

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

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(os.path.join(CERT_DIR, f"crt_{common_name}.crt"), "w") as f:
        json.dump({"type": "cert", "content": cert_pem.decode()}, f, indent=2)

    return {
        "crt": cert_pem.decode()
    }

@app.post("/crypto/validate")
async def validate_certificate(body: CertificateRequest, _: str = Depends(verify_api_key)):
    global ca_certificate
    if not ca_certificate:
        raise HTTPException(status_code=400, detail="CA not initialized")

    try:
        cert = x509.load_pem_x509_certificate(body.crt.encode())
        ca_public_key = ca_certificate.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return {"valid": True}
    except Exception:
        return {"valid": False}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
