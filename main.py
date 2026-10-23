import base64
import binascii
import os
from contextlib import asynccontextmanager

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict


# Load values from a local .env file when present. Platform environment
# variables still take precedence, as python-dotenv does not override them.
load_dotenv()


AAD = bytes(
    [
        0x80, 0x53, 0x1C, 0x87, 0xA0, 0x42, 0x69, 0x10,
        0xA2, 0xEA, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D,
    ]
)


def load_master_key() -> bytes:
    """Read and validate the Java-compatible Base64URL AES key."""
    encoded = os.getenv("MASTER_KEY", "")
    if not encoded:
        raise RuntimeError("MASTER_KEY is required; set it to a Base64URL-encoded AES key.")

    try:
        # Java's URL encoder retains padding. Require valid Base64 syntax and
        # accept only the URL-safe alphabet (including normal '=' padding).
        key = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("MASTER_KEY must be valid Base64URL (padding is allowed).") from exc

    if len(key) not in (16, 24, 32):
        raise RuntimeError(
            f"MASTER_KEY decodes to {len(key)} bytes; AES requires 16, 24, or 32 bytes."
        )
    return key


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail immediately on startup for missing or invalid configuration.
    load_master_key()
    yield


app = FastAPI(
    title="Java-compatible AES-GCM API",
    description="Encrypt and decrypt UTF-8 text using the configured Java-compatible AES-GCM key and AAD.",
    lifespan=lifespan,
)


class TextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str


class EncryptResponse(BaseModel):
    encrypted: str


class DecryptResponse(BaseModel):
    text: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/encrypt", response_model=EncryptResponse)
def encrypt(request: TextRequest) -> EncryptResponse:
    key = load_master_key()  # Revalidate if configuration changes after startup.
    iv = os.urandom(12)
    ciphertext_and_tag = AESGCM(key).encrypt(iv, request.text.encode("utf-8"), AAD)

    # Python AESGCM and Java GCMParameterSpec both append the 16-byte tag to
    # the ciphertext. Java Base64.getUrlEncoder() keeps '=' padding by default.
    encoded_iv = base64.urlsafe_b64encode(iv).decode("ascii")
    encoded_payload = base64.urlsafe_b64encode(ciphertext_and_tag).decode("ascii")
    return EncryptResponse(encrypted=f"{encoded_iv}:{encoded_payload}")


class DecryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    encrypted: str


@app.post("/decrypt", response_model=DecryptResponse)
def decrypt(request: DecryptRequest) -> DecryptResponse:
    key = load_master_key()
    parts = request.encrypted.split(":")
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Expected Base64URL(IV):Base64URL(ciphertext+tag).")
    try:
        iv = base64.b64decode(parts[0], altchars=b"-_", validate=True)
        ciphertext_and_tag = base64.b64decode(parts[1], altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Input contains invalid Base64URL data.") from exc
    if len(iv) != 12:
        raise HTTPException(status_code=400, detail="IV must be exactly 12 bytes.")
    if len(ciphertext_and_tag) < 16:
        raise HTTPException(status_code=400, detail="Ciphertext must include the 16-byte GCM tag.")
    try:
        plaintext = AESGCM(key).decrypt(iv, ciphertext_and_tag, AAD)
        return DecryptResponse(text=plaintext.decode("utf-8"))
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Decryption failed: invalid key, AAD, or encrypted value.") from exc
