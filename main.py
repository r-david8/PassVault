import itertools
import datetime
import bcrypt
import os

class pw:
    
    id_iter = itertools.count()

    def __init__(self, passW, gmail, site):
        self.ID = next(pw.id_iter)
        self.passW = passW
        self.gmail = gmail
        self.site = site
        self.updatedAt = datetime.datetime.now()

path = "passVault/user.txt"

if os.stat(path).st_size == 0:
    pw = input("Enter your password for your vault: ").encode("utf-8")
    s = bcrypt.gensalt()
    h = bcrypt.hashpw(pw, s)

    with open(path, "a") as f:
        f.write(h.decode())

else:
    passW = input("Enter your password: ").encode("utf-8")
    with open("passVault/user.txt", "r") as f:
        stored_hash = f.read().encode()

    if bcrypt.checkpw(passW, stored_hash):
        print("Logged in!")
    else:
        print("Incorrect password.")