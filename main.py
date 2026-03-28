from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import datetime
import bcrypt
import os
import json

open("user.key", "a")

KDF_ITERATIONS = 390000
SALT_BYTES = 16

def Log(a):
    now = str(datetime.datetime.now())

    f = {
        "status" : "Failed",
        "time" : now
    }

    t = {
        "status" : "SucsessFull",
        "time" : now
    }

    if os.path.exists("log.json") and os.path.getsize("log.json") > 0:
        with open('log.json', 'r') as file:
            data = json.load(file)
    else:
        data = {"logs": []}

    if a == True:
        data["logs"].append(t)
    else:
        data["logs"].append(f)

    with open('log.json', 'w') as file:
        json.dump(data, file, indent=4)

def AddRecord():
    now = str(datetime.datetime.now())
    master_pw = input("Enter your vault password to unlock records: ").encode("utf-8")

    name = input("Name of the site tha password belongs to: ")
    identifier = input("Gmail or username that belongs to the password: ")
    passW = input("Password that belongs to the account: ")

    record = {
        "Name": name,
        "Identifier": identifier,
        "Pw": passW,
        "UpdatedAt": now,
    }

    data = load_records(master_pw)
    data["records"].append(record)
    save_records(data, master_pw)

    
def show_record_by_name(password: bytes) -> None:
    data = load_records(password)
    records = data.get("records", [])
    if not records:
        print("No records found.")
        return
    name = input("Enter record name: ").strip().lower()
    exact = [r for r in records if r.get("Name", "").strip().lower() == name]
    if exact:
        for r in exact:
            print(json.dumps(r, indent=4))
        return
    partial = [r for r in records if name in r.get("Name", "").strip().lower()]
    if partial:
        for r in partial:
            print(json.dumps(r, indent=4))
        return
    print("No record found with that name.")
    

def showallrecords(password: bytes) -> None:
    data = load_records(password)
    records = data.get("records", [])
    if not records:
        print("No records found.")
        return
    for i, r in enumerate(records):
        name = r.get("Name", "<no name>")
        print(f"{i+1}. {name}")

#def UpdateRecord():



#def DeleteRecord():



def LogIn():
    passW = input("Enter your password: ").encode("utf-8")
    with open("user.key", "r") as f:
        stored_hash = f.read().encode()

    if bcrypt.checkpw(passW, stored_hash):
        print("Logged in!")
        Log(True)
        master_pw = passW
        while True:
            print("Write 1 to add a new record")
            print("Write 2 to update a record")
            print("Write 3 to delete a record")
            print("Write 4 to show a record by name")
            print("Write 5 to show all the record names")
            print("Type 'exit' to logout")
            command = input().strip()
            if command.lower() == "exit":
                break
            match command:
                case "1":
                    AddRecord()
                case "2":
                    print("Update not implemented yet.")
                case "3":
                    print("Delete not implemented yet.")
                case "4":
                    show_record_by_name(master_pw)
                case "5":
                    showallrecords(master_pw)
                case _:
                    print("Option not implemented yet.")

    else:
        print("Incorrect password.")
        Log(False)
        LogIn()


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def load_records(password: bytes) -> dict:
    if os.path.exists("record.json") and os.path.getsize("record.json") > 0:
        with open("record.json", "r", encoding="utf-8") as f:
            try:
                meta = json.load(f)
            except Exception:
                return {"records": []}

        if isinstance(meta, dict) and "salt" in meta and "data" in meta:
            salt = base64.b64decode(meta["salt"].encode())
            key = derive_key(password, salt)
            f = Fernet(key)
            try:
                decrypted = f.decrypt(meta["data"].encode())
                return json.loads(decrypted.decode("utf-8"))
            except InvalidToken:
                print("Unable to decrypt records: invalid password or corrupted file.")
                return {"records": []}
        if isinstance(meta, dict) and "records" in meta:
            salt = secrets.token_bytes(SALT_BYTES)
            key = derive_key(password, salt)
            f = Fernet(key)
            token = f.encrypt(json.dumps(meta).encode("utf-8"))
            new_meta = {"salt": base64.b64encode(salt).decode(), "data": token.decode()}
            with open("record.json", "w", encoding="utf-8") as out:
                json.dump(new_meta, out, indent=4)
            return meta

    return {"records": []}






def save_records(records: dict, password: bytes) -> None:
    salt = None
    if os.path.exists("record.json") and os.path.getsize("record.json") > 0:
        with open("record.json", "r", encoding="utf-8") as f:
            try:
                meta = json.load(f)
                if isinstance(meta, dict) and "salt" in meta:
                    salt = base64.b64decode(meta["salt"].encode())
            except Exception:
                salt = None

    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)

    key = derive_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(json.dumps(records).encode("utf-8"))
    meta = {"salt": base64.b64encode(salt).decode(), "data": token.decode()}
    with open("record.json", "w", encoding="utf-8") as out:
        json.dump(meta, out, indent=4)

def Register():
    pw = input("Enter your password for your vault: ").encode("utf-8")
    s = bcrypt.gensalt()
    h = bcrypt.hashpw(pw, s)

    with open("user.key", "w") as f:
        f.write(h.decode())



if os.stat("user.key").st_size == 0:
    Register()
    LogIn()
else:
    LogIn()
