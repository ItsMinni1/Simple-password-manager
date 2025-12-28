import json, hashlib, getpass, os, pyperclip, sys
from cryptography.fernet import Fernet

def hashPassword(password):
    sha256=hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

def generateKey():
    return Fernet.generate_key()

def initializeCipher(key):
    return Fernet(key)

def encryptPassword(cipher, password):
    return cipher.encrypt(password.encode()).decode()

def decryptPassword(cipher, encryptedPassword):
    return cipher.decrypt(encryptedPassword.encode()).decode()

def register(username, masterPassword):
    hashedMasterPassword = hashPassword(masterPassword)
    userData = {'username': username, 'masterPassword': hashedMasterPassword}
    fileName = 'userData.json'
    if os.path.exists(fileName) and os.path.getsize(fileName)==0:
        with open(fileName, 'w') as file:
            json.dump(userData, file)
            print("\n[+] Registration complete!! \n")
    else:
        with open(fileName, 'x') as file:
            json.dump(userData, file)
            print("\n[+] Registration complete!! \n")

def login(username, enteredPassword):
    try:
        with open('userData.json', 'r') as file:
            userData = json.load(file)
        storedPasswordHash = userData.get('masterPassword')
        enteredPasswordHash = hashPassword(enteredPassword)
        if enteredPasswordHash == storedPasswordHash and username == userData.get('username'):
            print("\n[+] Login Successful.. \n")
        else:
            print("\n[-] Invalid login credentials. Please use the credentials you used to register.")
            sys.exit()
    except Exception:
        print("\n[-] You have not registered, please do it :( \n")
        sys.exit()


def viewWebsites():
    try:
        with open('passwords.json', 'r') as data:
            view = json.load(data)
            print("\n Websites you have saved... \n")
            for x in view:
                print(x['website'])
            print('\n')
    except FileNotFoundError:
        print("\n[-] You have not saved any passwords ;-; \n")


key_fileName = 'encryptionKey.key'
if os.path.exists(key_fileName):
    with open(key_fileName, 'rb') as keyFile:
        key = keyFile.read()
else:
    key = generateKey()
    with open(key_fileName, 'wb') as keyFile:
        keyFile.write(key)

cipher = initializeCipher(key)

def addPassword(website, password):
    if not os.path.exists('passwords.json'):
        data = []
    else:
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []
    encryptedPassword = encryptPassword(cipher, password)
    passwordEntry = {'website': website, 'password': encryptedPassword}
    data.append(passwordEntry)
    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)

def getPassword(website):
    if not os.path.exists('passwords.json'):
        return None
    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []
    for entry in data:
        if entry['website'] == website:
            decryptedPassword = decryptPassword(cipher, entry['password'])
            return decryptedPassword
    return None

while True:
    print("1. Register")
    print("2. Login")
    print("3. Quit")
    choice = input("Enter your choice: ")
    if choice == '1':
        file = 'userData.json'
        if os.path.exists(file) and os.path.getsize(file) != 0:
            print("\n[-] Master user already exists!")
            sys.exit()
        else:
            username = input("Enter your username: ")
            masterPassword = getpass.getpass("Enter your master password: ")
            register(username, masterPassword)
    elif choice == '2':
        file = 'userData.json'
        if os.path.exists(file):
            username = input("Enter your username: ")
            masterPassword = getpass.getpass("Enter your master password: ")
            login(username, masterPassword)
        else:
            print("\n[-] You are not registered. Please register before attempting to log in :/ ")
            sys.exit()
        while True:
            print("1. Add Password")
            print("2. Get Password")
            print("3. View saved websites")
            print("4. Quit")
            passwordChoice = input("Enter your choice: ")
            if passwordChoice == '1':
                website = input("Enter website: ")
                password = getpass.getpass("Enter password: ")
                addPassword(website, password)
                print("\n[+] Password Added!! Yay :D ")
            elif passwordChoice == '2':
                website = input("Enter website: ")
                decryptedPassword = getPassword(website)
                if website and decryptedPassword:
                    pyperclip.copy(decryptedPassword)
                    print(f"\n[+] Password for {website}: {decryptedPassword}\n[+] Password also copied to clipboard. \n")
                else:
                    print("\n[-] Password not found :( Did you save the password? (I am not gaslighting.. or am I?) ")
                    print("\n[-] Use option 3 to see the websites you saved you dimbo >:( ")
            elif passwordChoice == '3':
                viewWebsites()
            elif passwordChoice == '4':
                break
    elif choice =='3':
        break