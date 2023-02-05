# encryption
import base64
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

# other
import json
import os
import tqdm
import sys

with open("params.json") as f: # You have to have already created the file and have put the params in it
    params = json.load(f)

password = input("Password : ")

if not params.get("salt"):
    params["salt"] = os.urandom(16).decode("latin1")
    params["status"] = "encrypting"

    if password != input("Confirm password : "):
        input("Passwords do not correspond.")
        sys.exit(0)
else:
    params["status"] = "decrypting"

password = password.encode() # Convert input to type bytes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=params["salt"].encode("latin1"),
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
fernet = Fernet(key)

for path, subdirs, files in tqdm.tqdm(os.walk(params["folder"])):
    for name in files:
        file_path = os.path.join(path, name)
        with open(file_path, 'rb') as f:
            data = f.read() # Read the bytes of the file

        if params["status"] == "encrypting":
            new_name = fernet.encrypt(name.encode())
            new_data = fernet.encrypt(data)
        else:
            try:
                new_name = fernet.decrypt(name.encode())
                new_data = fernet.decrypt(data)
            except InvalidToken as e:
                input("Wrong password.")
                sys.exit(0)

        with open(file_path, 'wb') as f:
            f.write(new_data) # Write the bytes to the file

        os.rename(file_path, os.path.join(path, new_name.decode()))

if params.pop("status") == "decrypting":
    params.pop("salt")

with open("params.json", "w") as f:
    json.dump(params, f)

input("Done.")