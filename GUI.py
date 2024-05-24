from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import os
import hashlib

def SHA_256(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature



def option():
    
    def add():
        # accepting input from the user
        username = entryName.get()
        # accepting password input from the user
        password = entryPassword.get()
        if username and password:
            with open("passwords.txt", 'a') as f:
                f.write(f"{username} {password}\n")
            messagebox.showinfo("Success", "Password added !!")
        else:
            messagebox.showerror("Error", "Please enter both the fields")


    def get():
        # accepting input from the user
        username = entryName.get()

        # creating a dictionary to store the data in the form of key-value pairs
        passwords = {}
        try:
            # opening the text file
            with open("passwords.txt", 'r') as f:
                for k in f:
                    i = k.split(' ')
                    # creating the key-value pair of username and password.
                    passwords[i[0]] = i[1]
        except:
            # displaying the error message
            print("ERROR !!")

        if passwords:
            mess = "Your passwords:\n"
            for i in passwords:
                if i == username:
                    mess += f"Password for {username} is {passwords[i]}\n"
                    break
            else:
                mess += "No Such Username Exists !!"
            messagebox.showinfo("Passwords", mess)
        else:
            messagebox.showinfo("Passwords", "EMPTY LIST!!")


    def getlist():
        # creating a dictionary
        passwords = {}

        # adding a try block, this will catch errors such as an empty file or others
        try:
            with open("passwords.txt", 'r') as f:
                for k in f:
                    i = k.split(' ')
                    passwords[i[0]] = i[1]
        except:
            print("No passwords found!!")

        if passwords:
            mess = "List of passwords:\n"
            for name, password in passwords.items():
                # generating a proper message
                mess += f"Password for {name} is {password}\n"
            # Showing the message
            messagebox.showinfo("Passwords", mess)
        else:
            messagebox.showinfo("Passwords", "Empty List !!")

    def delete():
        # accepting input from the user
        username = entryName.get()

        # creating a temporary list to store the data
        temp_passwords = []

        # reading data from the file and excluding the specified username
        try:
            with open("passwords.txt", 'r') as f:
                for k in f:
                    i = k.split(' ')
                    if i[0] != username:
                        temp_passwords.append(f"{i[0]} {i[1]}")

            # writing the modified data back to the file
            with open("passwords.txt", 'w') as f:
                for line in temp_passwords:
                    f.write(line)

            messagebox.showinfo(
                "Success", f"User {username} deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error deleting user {username}: {e}")
    
    app = Tk()
    windowWidth = app.winfo_reqwidth()
    windowHeight = app.winfo_reqheight()
    positionRight = int(app.winfo_screenwidth()/2 - windowWidth/2)
    positionDown = int(app.winfo_screenheight()/2 - windowHeight/2)
    app.geometry("+{}+{}".format(positionRight, positionDown))
    app.title("PassManager")

    # Username block
    labelName = Label(app, text="App Name:")
    labelName.grid(row=0, column=0, padx=15, pady=15)
    entryName = Entry(app)
    entryName.grid(row=0, column=1, padx=15, pady=15)

    # Password block
    labelPassword = Label(app, text="Password:")
    labelPassword.grid(row=1, column=0, padx=10, pady=5)
    entryPassword = Entry(app, show = "*")
    entryPassword.grid(row=1, column=1, padx=10, pady=5)

    # Add button
    buttonAdd = Button(app, text="Add", command=add)
    buttonAdd.grid(row=2, column=0, padx=15, pady=8, sticky="we")

    # Get button
    buttonGet = Button(app, text="Get", command=get)
    buttonGet.grid(row=2, column=1, padx=15, pady=8, sticky="we")

    # List Button
    buttonList = Button(app, text="List", command=getlist)
    buttonList.grid(row=3, column=0, padx=15, pady=8, sticky="we")

    # Delete button
    buttonDelete = Button(app, text="Delete", command=delete)
    buttonDelete.grid(row=3, column=1, padx=15, pady=8, sticky="we")




def match(event):
    if passw1.get() == "" or passw2.get() == "":
        # Password entries are empty
        print(passw1.get())
        messagebox.showerror("Error", "Both entry boxes neeeded to be filled")
        passw1.delete('0', END)
        passw2.delete('0', END)
    elif passw1.get() != passw2.get():
        # Passwords do not match
        messagebox.showerror("Error", "Passwords don't match!!!")
        passw1.delete('0', END)
        passw2.delete('0', END)    
    else:
        # Passwords match and valid
        added = passw1.get()
        win.withdraw()
        
        # Add new data.txt files
        
        data = open("data.txt", "a")  
        datad = open(dirpath.replace("\\", "/").replace("C:", "") + "/Data/data.txt", "a")
        data.write("@4tBp:>s#&^" + SHA_256(added) + "\n")
        datad.write("@4tBp:>s#&^" + SHA_256(added) + "\n")
        data.close()
        datad.close()
        option()



def checkpassword(event):
    
    # Removes \n
    
    temp = []
    dirpath = os.getcwd()
    data = open(dirpath.replace("\\", "/").replace("C:", "") + "/Data/data.txt", "r")
    key = data.readline().split("@4tBp:>s#&^")[-1][::-1].split("\n", 1)[-1][::-1]
    data.close()
    
    # Confirms Password
    
    if SHA_256(passw.get()) != key:
        messagebox.showerror("Warning", "Incorrect Password, Access Denied")
        passw.delete(0,END)
    else:
        win.destroy()
        option()

win = Tk()

# Sets the window to the middle of the screen

windowWidth = win.winfo_reqwidth()
windowHeight = win.winfo_reqheight()
positionRight = int(win.winfo_screenwidth()/2 - windowWidth/2)
positionDown = int(win.winfo_screenheight()/2 - windowHeight/2)
win.geometry("+{}+{}".format(positionRight, positionDown))

#starter

verify = 0
words = []
code = ("@ 4 t B p : > s # & ^")
code = code.split(" ")
dirpath = os.getcwd()
data = open(dirpath.replace("\\", "/").replace("C:", "") + "/Data/data.txt", "r")
for word in data.readline():
    if word != "\n":
        words.append(word)
data.close()
try:
    for run in range(len(code)):
        if words[run] == code[run]:
            verify += 1
except:
    verify = 0
        
if verify == len("@4tBp:>s#&^"):

    #password box
    
    win.title("PassManager")
    Label(win, text = "   Enter password to have access to the program   ", fg = "red").grid(row = 0, columnspan = 2, pady = 2)
    Label(win, text = "Password:").grid(row = 2, sticky = E, pady = 6)
    passw = Entry(win, show = "*")
    passw.grid(row = 2, column = 1, sticky = W)
    
    #check button
    
    equal = Button(win, text = "Submit", width = 10, bg = "red")
    equal.bind("<Button-1>", checkpassword)
    equal.grid(row = 3,column = 1, sticky = W)

else:   
    
    #middle screen
    
    win.geometry("+{}+{}".format(positionRight, positionDown))
    win.title("Setup")
    
    #new user text
    
    Label(win, text = "Looks like you are a new user", fg = "red", font = ("ariel", 12)).grid(row = 0)
    Label(win, text = "Create a password below so that you can use the program successfully everytime you login").grid(row = 1, pady = 15)
    
    #password box and entry
    
    Label(win, text = " New Password").grid(row = 2, padx = 20, sticky = W)
    passw1 = Entry(win, width = 40, show = "*")
    passw1.grid(row = 2, padx = 110, sticky = W)
    
    Label(win, text = " Confirm Password").grid(row = 3, sticky = W)
    passw2 = Entry(win, width = 40, show = "*")
    passw2.grid(row = 3, pady = 5, padx = 110, sticky = W) 
    
    #proceed button
    
    proceed = Button(win, text = "Proceed>", width = 10)
    proceed.bind("<Button-1>", match)
    proceed.grid(row = 4, pady = 10)



win.mainloop()