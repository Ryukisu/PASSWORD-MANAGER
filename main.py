# NECESSARY IMPORTS
import tkinter
from tkinter import *
from tkinter import ttk
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
from random import choice
from PIL import ImageTk

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
salt = b'\xcf8\xd8\x82O\x17Q\x88\x85\xc2\xb3\xd5\x95\x13v\xdd'

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
        self.dialog.title("Wprowadź dane:")
        self.dialog.iconbitmap("DragonPasswordManager_icon.ico")

        dialog_width = 350
        dialog_height = 200
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - dialog_width) / 2
        y = (screen_height - dialog_height) / 2
        self.dialog.geometry(f'{dialog_width}x{dialog_height}+{int(x)}+{int(y)}')
        self.dialog.configure(bg="#9FFFCB")

        self.dialog.columnconfigure(0, weight=1)
        self.dialog.columnconfigure(1, weight=3)

        site_label = Label(self.dialog, text="Strona*:", bg="#9FFFCB", font=("Montserrat", 10))
        site_label.grid(column=0, row=0, sticky=tkinter.E, padx=5, pady=5)
        self.site_entry = Entry(self.dialog)
        self.site_entry.grid(column=1, row=0, sticky=tkinter.W, padx=5, pady=5)

        username_label = Label(self.dialog, text="Nazwa użytkownika:", bg="#9FFFCB", font=("Montserrat", 10))
        username_label.grid(column=0, row=1, sticky=tkinter.E, padx=5, pady=5)
        self.username_entry = Entry(self.dialog)
        self.username_entry.grid(column=1, row=1, sticky=tkinter.W, padx=5, pady=5)

        email_label = Label(self.dialog, text="E-mail*:", bg="#9FFFCB", font=("Montserrat", 10))
        email_label.grid(column=0, row=2, sticky=tkinter.E, padx=5, pady=5)
        self.email_entry = Entry(self.dialog)
        self.email_entry.grid(column=1, row=2, sticky=tkinter.W, padx=5, pady=5)

        password_label = Label(self.dialog, text="Hasło*:", bg="#9FFFCB", font=("Montserrat", 10))
        password_label.grid(column=0, row=3, sticky=tkinter.E, padx=5, pady=5)
        self.password_entry = Entry(self.dialog, show="*")
        self.password_entry.grid(column=1, row=3, sticky=tkinter.W, padx=5, pady=5)

        submit_button = Button(self.dialog, text="DODAJ", command=self.submit_data,
                               bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
        submit_button.grid(column=1, row=4, sticky=tkinter.SW, padx=5, pady=5)

        info = Label(self.dialog, text="* pole obowiązkowe", bg="#9FFFCB", font=("Montserrat", 8, "italic", "bold"))
        info.grid(column=1, row=5, sticky=tkinter.NW, padx=5, pady=5)


    def submit_data(self):
        site = self.site_entry.get()
        username = self.username_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()

        if site and email and password:
            site = encrypt(self.site_entry.get().encode(), encryptionKey)
            username = encrypt(self.username_entry.get().encode(), encryptionKey)
            email = encrypt(self.email_entry.get().encode(), encryptionKey)
            password = encrypt(self.password_entry.get().encode(), encryptionKey)
            insert_fields = """INSERT INTO vault(site,username,email,password)
                    VALUES(?, ?, ?, ?)"""

            cursor.execute(insert_fields, (site, username, email, password))
            db.commit()
            messagebox.showinfo("SUKCES!", "Dodano nowe dane.")
            self.dialog.destroy()
        else:
            messagebox.showerror("BŁĄD!", "Proszę wypełnić wszystkie pola obowiązkowe.")

        passwordVault()


class GeneratePasswordDialog:
    def __init__(self, parent):
        self.dialog = Tk()
        self.dialog.title("Wygeneruj silne hasło")
        self.dialog.iconbitmap("DragonPasswordManager_icon.ico")

        dialog_width = 500
        dialog_height = 400
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - dialog_width) / 2
        y = (screen_height - dialog_height) / 2
        self.dialog.geometry(f'{dialog_width}x{dialog_height}+{int(x)}+{int(y)}')
        self.dialog.configure(bg="#9FFFCB")

        self.dialog.columnconfigure(0, weight=1)
        self.dialog.columnconfigure(1, weight=3)


        # window layout
        lenght_label = Label(self.dialog, text="Długość hasła:", bg="#9FFFCB",
                           font=("Montserrat", 12, "bold"))
        lenght_label.grid(column=0, row=0, sticky=tkinter.W, padx=40, pady=(20,5))

        slider_value = ttk.Label(self.dialog, text="8", background="#9FFFCB",
                                 font=("Montserrat", 12, "bold"))

        def slider_changed(event):
            slider_value.config(text=f'{int(slider.get())}')
            maks = int(slider.get())
            return maks

        slider_value.grid(column=0, row=1, sticky=tkinter.E, padx=(0,200))

        slider = ttk.Scale(self.dialog, from_=1, to=48, orient=HORIZONTAL,
                       length=200, variable=IntVar(), command=slider_changed)
        slider.set(8)
        slider.grid(column=0, row=1, sticky=tkinter.W, padx=(50,40))


        # numbers_label = Label(self.dialog, text="Liczby:", bg="#9FFFCB",
        #                        font=("Montserrat", 12))
        # numbers_label.grid(column=0, row=2, sticky=tkinter.W, padx=40, pady=5)
        #
        #
        # var1 = IntVar()
        # number_checkbox = Checkbutton(self.dialog, variable=var1, bg="#9FFFCB", activebackground="#9FFFCB",
        #                               onvalue=1, offvalue=0)
        # number_checkbox.grid(column=0, row=2, padx=30)
        # var1.set(0)
        # number_checkbox.var = var1
        #
        # special_label = Label(self.dialog, text="Znaki specjalne:", bg="#9FFFCB",
        #                        font=("Montserrat", 12))
        # special_label.grid(column=0, row=3, sticky=tkinter.W, padx=40, pady=5)

        password_label = Label(self.dialog, text="Twoje hasło:", bg="#9FFFCB",
                               font=("Montserrat", 12, "bold"))
        password_label.grid(column=0, row=4, sticky=tkinter.W, padx=40, pady=5)

        password_show = Entry(self.dialog, bg="#9FFFCB", font=("Montserrat", 12), width=420)
        password_show.insert(0, "")
        password_show.config(state="readonly", readonlybackground="#9FFFCB")
        password_show.grid(column=0, row=5, padx=20)

        # shuffle_label = Label(self.dialog, text="Wymieszaj:", bg="#9FFFCB",
        #                        font=("Montserrat", 12))
        # shuffle_label.grid(column=0, row=6, sticky=tkinter.W, padx=40, pady=5)

        # generating passwords


        def generate_words():
            # PAMIĘTAĆ O TYM ŻEBY BYŁY DUŻE I MAŁE LITERY
            password_words = []
            with open("assets/words.txt", "r") as file:
                word_list = list(file)
                maks = int(slider.get())
                for words in range(0, 8):
                    random_index = random.randint(0, len(word_list) - 1)
                    password_words.append(word_list[random_index].rstrip())
            generated_password = ''.join(password_words)
            generated_password = ''.join(choice((str.upper, str.lower))(char) for char in generated_password)
            if len(generated_password) > maks:
                generated_password = generated_password[0:maks]
            return generated_password

        def generate_special():
            special_char = """!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
            password_special = ''
            count = 0
            amount = random.randint(2,4)
            while count <= amount:
                password_special += special_char[random.randint(0, len(special_char)-1)]
                count += 1

            return password_special

        def generate_numbers():
            password_number = ''
            amount = random.randint(2,5)
            count = 0

            while count <= amount:
                password_number += str(random.randint(0,9))
                count += 1
            return password_number

        def generate_password():
            generated_password = generate_words()
            maks = len(generated_password)
            numbers = generate_numbers()
            special = generate_special()
            generated_password = numbers + special + generated_password
            generated_password = ''.join(random.sample(generated_password, len(generated_password)))
            generated_password = generated_password[0:maks]

            password_show.config(state=NORMAL)
            password_show.delete(0, END)
            password_show.insert(0, generated_password)
            password_show.config(state="readonly")

        btn = Button(self.dialog, text="GENERUJ", command=generate_password,
                               bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
        btn.grid(column=0, row=7, sticky=tkinter.W, padx=(40,140), pady=5)

        def copy_generated_password():
            pyperclip.copy(password_show.get())
            self.dialog.destroy()

        btncopy = Button(self.dialog, text="KOPIUJ", command=copy_generated_password,
                               bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
        btncopy.grid(column=0, row=7, sticky=tkinter.W, padx=(140,40), pady=5)



# MAIN WINDOW
window = Tk()
window.title("Dragon Password Manager")
window.iconbitmap("DragonPasswordManager_icon.ico")
window.configure(bg="#9FFFCB")


def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def firstLogin():
    for widget in window.winfo_children():
        widget.destroy()

    # wyśrodkowanie okna aplikacji
    app_width = 400
    app_height = 230
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    # zawartość okna pierwszego logowania
    lbl = Label(window, text="Utwórz główne hasło", bg="#9FFFCB", font=("Montserrat", 12))
    lbl.config(anchor=CENTER)
    lbl.pack(pady=(10, 5))

    passwordEntry = Entry(window, width=30, show="*", font=10)
    passwordEntry.pack()
    passwordEntry.focus()

    lbl2 = Label(window, text="Wprowadź ponownie główne hasło", bg="#9FFFCB", font=("Montserrat", 12))
    lbl2.config()
    lbl2.pack(pady=(20, 5))

    passwordCheckEntry = Entry(window, width=30, show="*", font=10)
    passwordCheckEntry.pack()
    passwordCheckEntry.focus()

    lblIncorect = Label(window, text="", bg="#9FFFCB")
    lblIncorect.config()
    lblIncorect.pack(pady=(10, 5))

    def returnPressed(event):
        saveMasterPassword()

    def saveMasterPassword():
        if passwordEntry.get() == passwordCheckEntry.get():
            lblIncorect.config(text="", bg="#9FFFCB")

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
            lblIncorect.config(text="Hasła nie są identyczne!", bg="#9FFFCB", font=("Montserrat", 10, "bold"))

    btn = Button(window, text="Zatwierdź", command=saveMasterPassword, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
    btn.pack(pady=10)
    # Umozliwienie zatwierdzenia hasła poprzez wciśnięcie klawisza ENTER
    window.bind('<Return>', returnPressed)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    # wyśrodkowanie okna aplikacji
    app_width = 600
    app_height = 210
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    # zawartość okna z kluczem bezpieczeństwa
    lbl = Label(window, text="Zapisz ten klucz, aby móc zresetować hasło główne", bg="#9FFFCB", font=("Montserrat", 13, "bold"))
    lbl.config(anchor=CENTER)
    lbl.pack(pady=(10, 5))

    lbl2 = Label(window, text=key, bg="#9FFFCB", font=("Montserrat", 14, "bold"))
    lbl2.config()
    lbl2.pack(pady=(20, 5))

    def copyKey():
        pyperclip.copy(lbl2.cget("text"))

    btn = Button(window, text="Skopiuj klucz", command=copyKey, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
    btn.pack(pady=5)

    def done():
        passwordVault()

    btn = Button(window, text="Zrobione!", command=done, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
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
    lbl = Label(window, text="Wprowadź klucz bezpieczeństwa", bg="#9FFFCB", font=("Montserrat", 12))
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30, font=10)
    txt.pack(pady=5)
    txt.focus()

    lbl2 = Label(window, bg="#9FFFCB")
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
            lbl2.config(text="Nieprawidłowy klucz", font=("Montserrat", 10, "bold"))

    btn = Button(window, text="Sprawdź klucz", command=checkRecoveryKey, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
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
    lbl = Label(window, bg="#9FFFCB", text="Wprowadź główne hasło", font=("Montserrat", 12))
    lbl.config(anchor=CENTER)
    lbl.pack()

    masterPasswordEntry = Entry(window, width=30, show="*", font=10)
    masterPasswordEntry.pack(pady=5)
    masterPasswordEntry.focus()

    lbl2 = Label(window, bg="#9FFFCB")
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
            lbl2.config(text="Nieprawidłowe hasło", bg="#9FFFCB", font=("Montserrat", 12, "bold"))
            window.destroy()


    btn = Button(window, text="Zatwierdź", command=checkMasterpassword, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
    btn.pack(pady=10)
    # Umozliwienie zatwierdzenia hasła poprzez wciśnięcie klawisza ENTER
    window.bind('<Return>', returnPressed)

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Zresetuj hasło", command=resetPassword, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
    btn.pack(pady=5)


# noinspection PyTypeChecker
def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    # Funkcje potrzebne do działania menadżera
    def generatePassword():
        GeneratePasswordDialog(window)
    def addEntry():
        InputDataDialog(window)

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    # centrowanie okna aplikacji
    app_width = 1450
    app_height = 800
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - app_width) / 2
    y = (screen_height - app_height) / 2
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    vaultFrame = Frame(window, bg="#9FFFCB")
    vaultFrame.grid()

    menuFrame = Frame(vaultFrame, bg="#9FFFCB")
    menuFrame.grid(row=0, column=0)

    lbl = Label(menuFrame, text="Dragon Password Manager", bg="#9FFFCB", font=("Montserrat", 14, "bold"), padx=10, pady=10)
    lbl.grid(column=0, row=0, sticky=tkinter.E)

    logo = ImageTk.PhotoImage(file="assets/logo.png")
    logo_lbl = Label(menuFrame, image=logo, bg="#9FFFCB")
    logo_lbl.image = logo
    logo_lbl.grid(column=0, row=1)

    btn = Button(menuFrame, text="Dodaj hasło", command=addEntry, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
    btn.grid(column=0, pady=10, padx=(0,105), row=2)
    btn = Button(menuFrame, text="Generuj hasło", command=generatePassword, bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
    btn.grid(column=0, pady=10, padx=(110,0), row=2)

    lbl = Label(vaultFrame, text="Strona", bg="#9FFFCB", font=("Montserrat", 14, "bold"))
    lbl.grid(row=0, column=1, padx=(0,0), pady=(150,0))
    lbl = Label(vaultFrame, text="Nazwa", bg="#9FFFCB", font=("Montserrat", 14, "bold"))
    lbl.grid(row=0, column=2, padx=(10,0), pady=(150,0))
    lbl = Label(vaultFrame, text="E-mail", bg="#9FFFCB", font=("Montserrat", 14, "bold"))
    lbl.grid(row=0, column=3, padx=(20,0), pady=(150,0))
    lbl = Label(vaultFrame, text="Hasło", bg="#9FFFCB", font=("Montserrat", 14, "bold"))
    lbl.grid(row=0, column=4, padx=(30,20), pady=(150,0))

    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()
            if (len(array) == 0):
                break

            lbl1 = Entry(vaultFrame, bg="#9FFFCB", font=("Montserrat", 12))
            lbl1.insert(0, (decrypt(array[i][1], encryptionKey)))
            lbl1.config(state="readonly", readonlybackground="#9FFFCB", bd=0)
            lbl1.grid(column=1, row=i+3, padx=(40,10))
            lbl1 = Entry(vaultFrame, bg="#9FFFCB", font=("Montserrat", 12))
            lbl1.insert(0, (decrypt(array[i][2], encryptionKey)))
            lbl1.config(state="readonly", readonlybackground="#9FFFCB", bd=0)
            lbl1.grid(column=2, row=i+3, padx=(20,20))
            lbl1 = Entry(vaultFrame, bg="#9FFFCB", font=("Montserrat", 12))
            lbl1.insert(0, (decrypt(array[i][3], encryptionKey)))
            lbl1.config(state="readonly", readonlybackground="#9FFFCB", bd=0)
            lbl1.grid(column=3, row=i+3, padx=(30,0))
            lbl2 = Entry(vaultFrame, bg="#9FFFCB", font=("Montserrat", 12))
            lbl2.insert(0, (decrypt(array[i][4], encryptionKey)))
            lbl2.config(state="readonly", readonlybackground="#9FFFCB", bd=0)
            lbl2.grid(column=4, row=i+3, padx=(50,20))

            btn = Button(vaultFrame, text="Usuń", command=partial(removeEntry, array[i][0]), bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
            btn.grid(column=0, row=i+3, pady=10, padx=(0, 80))

            def copyEntry(input):
                cursor.execute("SELECT password FROM vault WHERE id = ?", (input,))
                data = cursor.fetchone()
                if data:
                    password = decrypt(data[0], encryptionKey)
                    password= str(password)
                    password = password[2:(len(password)-1)]
                    pyperclip.copy(password)
            btn = Button(vaultFrame, text="Kopiuj hasło", command= partial(copyEntry, array[i][0]), bg="#25A18E",
                 font=("Montserrat", 10, "bold"), fg="white")
            btn.grid(column=0, row=i+3, pady=10, padx=(80, 0))

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

# TODO: - scrollbar;
#       - opcja zmiany hasła w danej domenie dla danego użytkownika;
#       - opcja kopiowania hasła do schowka;
#       - generuj bezpieczne hasło;
#       - [OPTIONAL] możliwość wyszukiwania;
#       - [OPTIONAL] przypominanie o zmianie hasła.
#       - dodać licznik błędnych wpisań głównego hasła!
