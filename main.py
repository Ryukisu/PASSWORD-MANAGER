# NECESSARY IMPORTS

# import tkinter as tk
from tkinter import *
from tkinter import simpledialog
from tkinter import messagebox
from functools import partial
import sqlite3
import hashlib
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import random

'''
# TO COPY - centrowanie okna aplikacji
app_width = 
app_height =
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x = (screen_width – app_width) / 2
y = (screen_height – app_height) / 2
window.geometry(f'{app_width}x{app_height}+{x}+{y}')
'''

# ENCRYPTION/ DECRYPTION
backend = default_backend()
salt = b'6969'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# DATA BASE
# Utworzenie bazy danych
with sqlite3.connect("DragonPasswordManager.db") as db:
    cursor = db.cursor()

# Utworzenie tabeli w bazie danych
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterPassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL,
counter INTEGER);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
site TEXT NOT NULL,
username,
email TEXT NOT NULL,
password TEXT NOT NULL);
""")

def deleteDB():
    sql = "DELETE FROM masterPassword WHERE id = 1"
    cursor.execute(sql)
    window.destroy()

# POP-UP
class InputDataDialog:
    def __init__(self, parent):
        self.dialog = Tk()
        self.dialog.title("Input Data")

        # Create labels and entry fields for each input
        site_label = Label(self.dialog, text="Site:")
        site_label.pack()
        self.site_entry = Entry(self.dialog)
        self.site_entry.pack()

        username_label = Label(self.dialog, text="Username:")
        username_label.pack()
        self.username_entry = Entry(self.dialog)
        self.username_entry.pack()

        email_label = Label(self.dialog, text="Email:")
        email_label.pack()
        self.email_entry = Entry(self.dialog)
        self.email_entry.pack()

        password_label = Label(self.dialog, text="Password:")
        password_label.pack()
        self.password_entry = Entry(self.dialog, show="*")
        self.password_entry.pack()

        # Create a button to submit the data
        submit_button = Button(self.dialog, text="Submit", command=self.submit_data)
        submit_button.pack()

    def submit_data(self):
        # Retrieve the entered values
        site = encrypt(self.site_entry.get().encode(), encryptionKey)
        username = encrypt(self.username_entry.get().encode(), encryptionKey)
        email = encrypt(self.email_entry.get().encode(), encryptionKey)
        password = encrypt(self.password_entry.get().encode(), encryptionKey)

        # site = encrypt(popUp(text1).encode(), encryptionKey)
        # username = encrypt(popUp(text2).encode(), encryptionKey)
        # email = encrypt(popUp(text3).encode(), encryptionKey)
        # password = encrypt(popUp(text4).encode(), encryptionKey)

        # Validate the data (you can add custom validation logic here)
        if site and email and password:
            messagebox.showinfo("Success", "Data submitted successfully!")
            self.dialog.destroy()
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

    def process_data(self, site, username, email, password):
        # cursor.execute("INSERT INTO vault VALUES (?, ?, ?, ?)", (site, username, email, password))
        # db.commit()

        insert_fields = """INSERT INTO vault(site,username,email,password)
        VALUES(?, ?, ?, ?)"""

        cursor.execute(insert_fields, (site, username, email, password))
        db.commit()

def popUp(text):
    answer = simpledialog.askstring("input string", text)
    return answer

# MAIN WINDOW
window = Tk()
window.title("Dragon Password Manager")
window.iconbitmap("DragonPasswordManager_icon.ico")


def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def firstLogin():
    for widget in window.winfo_children():
        widget.destroy()

    # wyśrodkowanie okna aplikacji
    app_width = 400
    app_height = 200
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    # zawartość okna pierwszego logowania
    lbl = Label(window, text="Utwórz główne hasło")
    lbl.config(anchor=CENTER)
    lbl.pack(pady=(10, 5))

    passwordEntry = Entry(window, width=30, show="*")
    passwordEntry.pack()
    passwordEntry.focus()

    lbl2 = Label(window, text="Wprowadź ponownie główne hasło")
    lbl2.config()
    lbl2.pack(pady=(20, 5))

    passwordCheckEntry = Entry(window, width=30, show="*")
    passwordCheckEntry.pack()
    passwordCheckEntry.focus()

    lblIncorect = Label(window, text="")
    lblIncorect.config()
    lblIncorect.pack(pady=(10, 5))

    def returnPressed(event):
        saveMasterPassword()

    def saveMasterPassword():
        if passwordEntry.get() == passwordCheckEntry.get():
            lblIncorect.config(text="")

            sql = "DELETE FROM masterPassword WHERE id = 1"

            cursor.execute(sql)

            hashedMasterPassword = hashPassword(passwordEntry.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(passwordEntry.get().encode()))

            insertPassword = """INSERT INTO masterPassword(password, recoveryKey, counter)
            VALUES(?, ?, 0)"""
            cursor.execute(insertPassword, ((hashedMasterPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lblIncorect.config(text="Hasła nie są identyczne!")

    btn = Button(window, text="Zatwierdź", command=saveMasterPassword)
    btn.pack(pady=10)
    # Umozliwienie zatwierdzenia hasła poprzez wciśnięcie klawisza ENTER
    window.bind('<Return>', returnPressed)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    # wyśrodkowanie okna aplikacji
    app_width = 400
    app_height = 200
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    # zawartość okna z kluczem bezpieczeństwa
    lbl = Label(window, text="Zapisz ten klucz, aby móc zresetować hasło główne")
    lbl.config(anchor=CENTER)
    lbl.pack(pady=(10, 5))

    lbl2 = Label(window, text=key)
    lbl2.config()
    lbl2.pack(pady=(20, 5))

    def copyKey():
        pyperclip.copy(lbl2.cget("text"))

    btn = Button(window, text="Skopiuj klucz", command=copyKey)
    btn.pack(pady=5)

    def done():
        passwordVault()

    btn = Button(window, text="Zrobione!", command=done)
    btn.pack(pady=5)

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    # wyśrodkowanie okna aplikacji
    app_width = 400
    app_height = 200
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    # zawartość okna resetowania hasła głównego
    lbl = Label(window, text="Wprowadź klucz bezpieczeństwa")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30)
    txt.pack(pady=5)
    txt.focus()

    lbl2 = Label(window)
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode("utf-8"))
        cursor.execute("SELECT * FROM masterPassword WHERE id = 1 AND recoveryKey = ?", [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()
        if checked:
            firstLogin()
        else:
            txt.delete(0, "end")
            lbl2.config(text="Nieprawidłowy klucz")

    btn = Button(window, text="Sprawdź klucz", command=checkRecoveryKey)
    btn.pack(pady=5)

def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    # wyśrodkowanie okna aplikacji
    app_width = 400
    app_height = 200
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    # zawartość okna logowania
    lbl = Label(window, text="Wprowadź główne hasło")
    lbl.config(anchor=CENTER)
    lbl.pack()

    masterPasswordEntry = Entry(window, width=30, show="*")
    masterPasswordEntry.pack(pady=5)
    masterPasswordEntry.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(masterPasswordEntry.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(masterPasswordEntry.get().encode()))
        if cursor.execute("SELECT * FROM masterPassword WHERE id = 1 AND password = ?", [(checkHashedPassword)]):
            return cursor.fetchall()

    def returnPressed(event):
        checkMasterpassword()

    def checkMasterpassword():
        match = getMasterPassword()

        if match:
            passwordVault()
        else:
            masterPasswordEntry.delete(0, "end")
            lbl2.config(text="Nieprawidłowe hasło")


    btn = Button(window, text="Zatwierdź", command=checkMasterpassword)
    btn.pack(pady=10)
    # Umozliwienie zatwierdzenia hasła poprzez wciśnięcie klawisza ENTER
    window.bind('<Return>', returnPressed)

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Zresetuj hasło", command=resetPassword)
    btn.pack(pady=5)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    # Funkcje potrzebne do działania menadżera
    def addEntry():
        # STARY SPOSÓB DODAWANIA HASŁA - DANE OSOBNO ZBIERANE
        # text1 = "Strona"
        # text2 = "Username"
        # text3 = "E-mail"
        # text4 = "Password"
        #
        #
        # site = encrypt(popUp(text1).encode(), encryptionKey)
        # username = encrypt(popUp(text2).encode(), encryptionKey)
        # email = encrypt(popUp(text3).encode(), encryptionKey)
        # password = encrypt(popUp(text4).encode(), encryptionKey)
        #
        # insert_fields = """INSERT INTO vault(site,username,email,password)
        # VALUES(?, ?, ?, ?)"""
        #
        # cursor.execute(insert_fields, (site, username, email, password))
        # db.commit()
        #
        # passwordVault()
        # NOWY SPOSÓB ZBIERANIA DANYCH - JEDNO OKNO
        data = InputDataDialog(window)
        data.process_data()
        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    # centrowanie okna aplikacji
    app_width = 1000
    app_height = 500
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    lbl = Label(window, text="Dragon Password Manager", font=52)
    lbl.grid(column=1)

    btn = Button(window, text="Dodaj hasło", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Site")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="E-mail")
    lbl.grid(row=2, column=2, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=3, padx=80)

    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()
            if (len(array) == 0):
                break

            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Montserrat", 12))
            lbl1.grid(column=0, row=i+3)
            lbl1 = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Montserrat", 12))
            lbl1.grid(column=1, row=i+3)
            lbl1 = Label(window, text=(decrypt(array[i][3], encryptionKey)), font=("Montserrat", 12))
            lbl1.grid(column=2, row=i+3)
            lbl2 = Label(window, text=(decrypt(array[i][4], encryptionKey)), font=("Montserrat", 12))
            lbl2.grid(column=3, row=i+3)

            btn = Button(window, text="Usuń", command=partial(removeEntry, array[i][0]))
            btn.grid(column=4, row=i+3, pady=10, padx=(0, 50))

            def copyEntry():
                pyperclip.copy(lbl2.cget("text"))

            btn = Button(window, text="Kopiuj", command=copyEntry)
            btn.grid(column=4, row=i+3, pady=10, padx=(50, 0))

            i = i+1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute("SELECT * FROM masterPassword")
if cursor.fetchall():
    loginScreen()
else:
    firstLogin()

window.mainloop()

# TODO:
#       - opcja zmiany hasła w danej domenie dla danego użytkownika;
#       - opcja kopiowania hasła do schowka;
#       - generuj bezpieczne hasło;
#       - [OPTIONAL] możliwość wyszukiwania;
#       - [OPTIONAL] przypominanie o zmianie hasła.
#       - dodać licznik błędnych wpisań głównego hasła!
