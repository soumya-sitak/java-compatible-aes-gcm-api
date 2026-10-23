# Java-compatible AES-GCM API

A small FastAPI service that encrypts arbitrary UTF-8 text and returns the same format as the Java implementation:

```text
Base64URL(12-byte IV):Base64URL(ciphertext + 16-byte GCM tag)
```

It uses the provided 16-byte AAD exactly:

```text
80 53 1C 87 A0 42 69 10 A2 EA 08 00 2B 30 30 9D
```

## Configure the key

`MASTER_KEY` must be Base64URL encoding of the *raw AES key bytes*: exactly 16, 24, or 32 bytes (AES-128, AES-192, or AES-256). Configure the same encoded key in the Java application. Do not use a password or a textual phrase as the key unless Java and Python both derive the same raw key bytes. The app automatically reads a `.env` file in its working directory; shell/platform environment variables take precedence.

The prior value `--o4Gg==` decodes to only 4 bytes, so it is not a valid AES key. This project does not replace or reinterpret it; the service refuses to start until a valid shared key is configured.

To generate a new random 32-byte key for a development setup, run:

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Copy that output into the Java application's key configuration and set the same value for this API. If Java already uses a different key, use that key instead. Keep keys out of source control and logs.

## Run locally

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# Put MASTER_KEY=... in .env, or export it in your shell.
uvicorn main:app --reload
```

On Windows PowerShell, set the variable with:

```powershell
$env:MASTER_KEY = "PASTE_THE_SHARED_BASE64URL_KEY_HERE"
uvicorn main:app --reload
```

The interactive API docs are at <http://127.0.0.1:8000/docs>.

## Encrypt with curl

```bash
curl -X POST http://127.0.0.1:8000/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"text":"anything you want to encrypt"}'
```

Example response (the IV is random, so each encryption produces a different string):

```json
{"encrypted":"RANDOM_12_BYTE_IV_BASE64URL==:CIPHERTEXT_AND_TAG_BASE64URL=="}
```

## Try it in Postman

1. Create a `POST` request to `http://127.0.0.1:8000/encrypt`.
2. Under **Body**, choose **raw** and **JSON**.
3. Send `{"text":"hello from Postman"}`.
4. Read the `encrypted` field in the JSON response.

## Decrypt (optional)

Send the returned string to `POST http://127.0.0.1:8000/decrypt`:

```bash
curl -X POST http://127.0.0.1:8000/decrypt \
  -H 'Content-Type: application/json' \
  -d '{"encrypted":"PASTE_THE_RETURNED_IV_COLON_CIPHERTEXT_HERE"}'
```

The response is `{"text":"anything you want to encrypt"}`. Decryption returns HTTP 400 if the value is malformed or its authentication tag does not verify (for example, because the key or AAD differs).

## Java compatibility notes

- Use `AES/GCM/NoPadding`, a 12-byte IV, a 128-bit authentication tag, and the exact AAD above.
- Feed Java the same raw AES key bytes. If Java stores the encoded key, decode it with the URL-safe Base64 decoder.
- Encode/decode each part with Java's `Base64.getUrlEncoder()` / `getUrlDecoder()`; the standard encoder retains padding, matching this API.
- AES-GCM uses a fresh random IV for every encryption. The encrypted output will not match byte-for-byte across separate encryptions, even for identical plaintext, but Java can decrypt it when key, IV, AAD, and format match.

Missing or invalid `MASTER_KEY` causes startup to fail with a clear error. The API also validates the key when handling each encrypt/decrypt request.
