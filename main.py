import itertools
import datetime
import bcrypt
import os

log = open("log.txt", "a")
user = open("user.txt", "a")
now = str(datetime.datetime.now())

class pw:
    
    id_iter = itertools.count()

    def __init__(self, name, identifier, passW):
        self.ID = next(pw.id_iter)
        self.identifier = identifier
        self.name = name
        self.passW = passW
        self.updatedAt = datetime.datetime.now()

    def __str__(self):
        return f"{self.ID} {self.name} {self.identifier} {self.passW}"

def Log(a):
    with open("log.txt", "r") as l:
        if a == True: 
            log.write("Login:        "+now+"\n")
        elif a == False:
            log.write("Failed login: "+now+"\n")


def AddRecord():
    name = input("Name of the site tha password belongs to: ")
    identifier = input("Gmail or username that belongs to the password: ")
    passW = input("Password that belongs to the account: ")
    record = pw(name, identifier, passW)

    print(record)


#def UpdateRecord():



#def DeleteRecord():



#def ShowRecord():



#def ShowAllRecordName():



def LogIn():
    passW = input("Enter your password: ").encode("utf-8")
    with open("user.txt", "r") as f:
        stored_hash = f.read().encode()

    if bcrypt.checkpw(passW, stored_hash):
        print("Logged in!")
        Log(True)

        print("Write 1 to add a new record")
        print("Write 2 to update a record")
        print("Write 3 to delete a record")
        print("Write 4 to show a record")
        print("Write 5 show all the record names")
        
        command = input()
        match command:
            case "1":
                AddRecord()
            

    else:
        print("Incorrect password.")
        Log(False)
        LogIn()

def Register():
    pw = input("Enter your password for your vault: ").encode("utf-8")
    s = bcrypt.gensalt()
    h = bcrypt.hashpw(pw, s)

    with open("user.txt", "w") as f:
        f.write(h.decode())



if os.stat("user.txt").st_size == 0:
    Register()
    LogIn()
else:
    LogIn()
