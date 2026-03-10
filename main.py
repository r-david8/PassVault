import itertools
import datetime
import bcrypt
import os
import json

open("user.txt", "a")


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

    name = input("Name of the site tha password belongs to: ")
    identifier = input("Gmail or username that belongs to the password: ")
    passW = input("Password that belongs to the account: ")

    record = {
        "Name" : name,
        "Identifier" : identifier,
        "Pw" : passW,
        "UpdatedAt" : now
    }

    if os.path.exists("record.json") and os.path.getsize("record.json") > 0:
        with open('record.json', 'r') as file:
            data = json.load(file)
    else:
        data = {"records": []}

    data["records"].append(record)

    with open('record.json', 'w') as file:
        json.dump(data, file, indent=4)

    
    


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
