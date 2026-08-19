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
import string


USER_KEY_FILE = "PassVault/user.key"
RECORD_FILE = "PassVault/record.json"
LOG_FILE = "PassVault/log.json"

KDF_ITERATIONS = 390000
SALT_BYTES = 16

# Stores the vault password only while the program is running.
# It is cleared when the user logs out.
SESSION_PASSWORD = None


def Log(success: bool):
    now = str(datetime.datetime.now())

    entry = {
        "status": "Successful" if success else "Failed",
        "time": now
    }

    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as file:
                data = json.load(file)
        except (json.JSONDecodeError, OSError):
            data = {"logs": []}
    else:
        data = {"logs": []}

    data.setdefault("logs", []).append(entry)

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def GeneratePass():
    # More secure than random.randint/random.shuffle for passwords.
    alphabet = string.ascii_letters + string.digits + string.punctuation

    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation),
    ]

    password.extend(
        secrets.choice(alphabet)
        for _ in range(11)
    )

    # Fisher-Yates shuffle using secrets.
    for i in range(len(password) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password[i], password[j] = password[j], password[i]

    generated = "".join(password)
    print(f"\nGenerated password:\n{generated}\n")

    return generated


def get_session_password() -> bytes:
    """
    Returns the password from the current authenticated session.
    """
    if SESSION_PASSWORD is None:
        raise RuntimeError("No active session. Please log in.")

    return SESSION_PASSWORD


def AddRecord():
    password = get_session_password()
    now = str(datetime.datetime.now())

    name = input("Name of the site the password belongs to: ").strip()
    identifier = input("Gmail or username that belongs to the password: ").strip()
    account_password = input("Password that belongs to the account: ")

    if not name:
        print("Record name cannot be empty.")
        return

    record = {
        "Name": name,
        "Identifier": identifier,
        "Pw": account_password,
        "UpdatedAt": now,
    }

    data = load_records(password)
    data.setdefault("records", []).append(record)
    save_records(data, password)

    print("Record added successfully.")

def show_all_records():
    password = get_session_password()
    data = load_records(password)
    records = data.get("records", [])

    if not records:
        print("\nNo records found.")
        return

    print("\n" + "=" * 50)
    print("ALL SAVED RECORDS")
    print("=" * 50)

    for i, record in enumerate(records, start=1):
        print(f"\nRecord #{i}")
        print("-" * 30)
        print(f"Name:       {record.get('Name', '<no name>')}")
        print(f"Identifier: {record.get('Identifier', '<none>')}")
        print(f"Password:   {record.get('Pw', '<none>')}")
        print(f"Updated:    {record.get('UpdatedAt', '<unknown>')}")

    print("\n" + "=" * 50)


def select_record(records):
    """
    Lets the user select a record by number.
    Returns its index or None.
    """
    if not records:
        print("No records found.")
        return None

    for i, record in enumerate(records, start=1):
        print(f"{i}. {record.get('Name', '<no name>')}")

    choice = input("\nSelect a record number: ").strip()

    try:
        index = int(choice) - 1
    except ValueError:
        print("Please enter a valid number.")
        return None

    if index < 0 or index >= len(records):
        print("Invalid record number.")
        return None

    return index


def UpdateRecord():
    password = get_session_password()
    data = load_records(password)
    records = data.get("records", [])

    print("\nChoose the record to update:")
    index = select_record(records)

    if index is None:
        return

    record = records[index]

    print("\nLeave a field empty to keep its current value.")

    new_name = input(
        f"New site name [{record.get('Name', '')}]: "
    ).strip()

    new_identifier = input(
        f"New username/email [{record.get('Identifier', '')}]: "
    ).strip()

    new_password = input(
        "New account password [hidden/current unchanged if empty]: "
    )

    if new_name:
        record["Name"] = new_name

    if new_identifier:
        record["Identifier"] = new_identifier

    if new_password:
        record["Pw"] = new_password

    record["UpdatedAt"] = str(datetime.datetime.now())

    save_records(data, password)
    print("Record updated successfully.")


def DeleteRecord():
    password = get_session_password()
    data = load_records(password)
    records = data.get("records", [])

    print("\nChoose the record to delete:")
    index = select_record(records)

    if index is None:
        return

    record = records[index]

    print(
        f"\nYou are about to delete: "
        f"{record.get('Name', '<no name>')}"
    )

    confirmation = input(
        "Type DELETE to permanently remove this record: "
    ).strip()

    if confirmation != "DELETE":
        print("Deletion cancelled.")
        return

    deleted = records.pop(index)
    save_records(data, password)

    print(
        f"Record '{deleted.get('Name', '<no name>')}' "
        f"deleted successfully."
    )


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )

    return base64.urlsafe_b64encode(kdf.derive(password))


def load_records(password: bytes) -> dict:
    if not os.path.exists(RECORD_FILE):
        return {"records": []}

    if os.path.getsize(RECORD_FILE) == 0:
        return {"records": []}

    try:
        with open(RECORD_FILE, "r", encoding="utf-8") as file:
            meta = json.load(file)
    except (json.JSONDecodeError, OSError):
        print("Unable to read the record file.")
        return {"records": []}

    # Encrypted format.
    if isinstance(meta, dict) and "salt" in meta and "data" in meta:
        try:
            salt = base64.b64decode(meta["salt"].encode("utf-8"))
            key = derive_key(password, salt)
            cipher = Fernet(key)

            decrypted = cipher.decrypt(
                meta["data"].encode("utf-8")
            )

            data = json.loads(decrypted.decode("utf-8"))
            data.setdefault("records", [])
            return data

        except (
            InvalidToken,
            ValueError,
            json.JSONDecodeError,
            TypeError,
        ):
            print(
                "Unable to decrypt records: "
                "invalid password or corrupted file."
            )
            return {"records": []}

    # Old plaintext format: encrypt it automatically.
    if isinstance(meta, dict) and "records" in meta:
        save_records(meta, password)
        return meta

    return {"records": []}


def save_records(records: dict, password: bytes) -> None:
    salt = None

    if os.path.exists(RECORD_FILE) and os.path.getsize(RECORD_FILE) > 0:
        try:
            with open(RECORD_FILE, "r", encoding="utf-8") as file:
                meta = json.load(file)

            if isinstance(meta, dict) and "salt" in meta:
                salt = base64.b64decode(
                    meta["salt"].encode("utf-8")
                )

        except (
            json.JSONDecodeError,
            OSError,
            ValueError,
            TypeError,
        ):
            salt = None

    # First save: create a salt.
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)

    key = derive_key(password, salt)
    cipher = Fernet(key)

    plaintext = json.dumps(records).encode("utf-8")
    token = cipher.encrypt(plaintext)

    meta = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "data": token.decode("utf-8")
    }

    with open(RECORD_FILE, "w", encoding="utf-8") as out:
        json.dump(meta, out, indent=4)


def Register():
    while True:
        pw = input(
            "Enter your password for your vault: "
        ).encode("utf-8")

        confirm = input(
            "Confirm your vault password: "
        ).encode("utf-8")

        if not pw:
            print("Password cannot be empty.")
            continue

        if pw != confirm:
            print("Passwords do not match. Try again.")
            continue

        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(pw, salt)

        with open(USER_KEY_FILE, "w", encoding="utf-8") as file:
            file.write(hashed.decode("utf-8"))

        print("Vault registered successfully.")
        return


def LogIn():
    global SESSION_PASSWORD

    try:
        with open(USER_KEY_FILE, "r", encoding="utf-8") as file:
            stored_hash = file.read().encode("utf-8")
    except OSError:
        print("Unable to read user key.")
        return

    while True:
        passW = input("Enter your password: ").encode("utf-8")

        if bcrypt.checkpw(passW, stored_hash):
            # Store the authenticated password for this running session.
            SESSION_PASSWORD = passW

            print("Logged in!")
            Log(True)
            break

        print("Incorrect password.")
        Log(False)

    while True:
        print("\n--- PASSWORD VAULT ---")
        print("Write 0 to generate a safe password")
        print("Write 1 to add a new record")
        print("Write 2 to update a record")
        print("Write 3 to delete a record")
        print("Write 4 to show all records")
        print("Enter to logout")

        command = input("> ").strip()

        if command.lower() == "":
            # Clear the password from the global variable.
            SESSION_PASSWORD = None
            print("Logged out.")
            break

        match command:
            case "0":
                GeneratePass()

            case "1":
                AddRecord()

            case "2":
                UpdateRecord()

            case "3":
                DeleteRecord()

            case "4":
                show_all_records()

            case _:
                print("Invalid option.")


def main():
    # Create the file if it does not exist.
    open(USER_KEY_FILE, "a").close()

    if os.path.getsize(USER_KEY_FILE) == 0:
        Register()

    LogIn()


if __name__ == "__main__":
    main()