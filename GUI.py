from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import os
import hashlib


def SHA_256(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature



def option():
    
    def add_Or_Update():
        # accepting input from the user
        username = entryName.get().capitalize()

        # accepting password input from the user
        password = entryPassword.get()

        # To handle the case when one of the fields is not filled up
        if not (username and password):
            messagebox.showerror("Error", "Please enter both the fields")
            return

        else:
        # Check if the app exists in the file
            passwords = {}
            try:
                with open("passwords.txt", 'r') as f:
                    for k in f:
                        i = k.strip().split(' ')
                        passwords[i[0]] = i[1]
            except FileNotFoundError:
                pass

            if username in passwords:
                # Update the password
                confirm = messagebox.askyesno("Confirm Update", f"The app '{username}' is already added.\nDo you still want to update your password?")
                if confirm:
                    passwords[username] = password
                    with open("passwords.txt", 'w') as f:
                        for user, pwd in passwords.items():
                            f.write(f"{user} {pwd}\n")
                    messagebox.showinfo("Success", f"Your password for '{username}' is updated successfully!")
            else:
                # Add the password if app is inexistent in the system
                confirm = messagebox.askyesno("Confirm Add", f"Verify and add the Password for {username}?\nPassword : {password}")
                if confirm:
                    with open("passwords.txt", 'a') as f:
                        f.write(f"{username} {password}\n")
                    messagebox.showinfo("Success", "Password added !!")


    def get():
        # accepting input from the user
        username = entryName.get().capitalize()

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

        if passwords and len(username) != 0:
            mess = "Your passwords:\n"
            for i in passwords:
                if i == username:
                    mess += f"Password for {username} is {passwords[i]}\n"
                    break
            else:
                mess += "No Such App Name Exists !!"
            messagebox.showinfo("Passwords", mess)
        elif len(username) == 0:
            messagebox.showerror("App Name", f"Please fill in the field: 'App Name'")
        else:
            messagebox.showerror("Error", f"No such app name: {username} exists!")


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
            list_win = Toplevel(app)
            list_win.title("List of Passwords")
            list_win.geometry("1000x1000")

            search_Var = StringVar()
            search_Var.trace('w', lambda name, index, mode: delayed_filter())

            top_frame = Frame(list_win)
            top_frame.pack(side=TOP, pady=10)

            search_label = Label(top_frame, text="App Search:", font=('Arial', 15, 'bold'), foreground='Red')
            search_label.pack(side=LEFT, padx=10)
            search_entry = Entry(top_frame, textvariable=search_Var, font=('Arial', 15), foreground='Red')
            search_entry.pack(side=LEFT, padx=10)

            tree = ttk.Treeview(list_win)
            tree["columns"] = ("App Name", "Password")
            tree.column("#0", width=0, stretch=NO)
            tree.column("App Name", anchor=W, width=150)
            tree.column("Password", anchor=W, width=150)

            tree.heading("#0", text="", anchor=W)
            tree.heading("App Name", text="App Name", anchor=W)
            tree.heading("Password", text="Password", anchor=W)

            def custom_sort_appKey(item):
                return item[0].upper()

            sorted_app_names = sorted(passwords.keys(), key=custom_sort_appKey)

            for idx, name in enumerate(sorted_app_names, 1):
                password = passwords[name]
                tree.insert(parent='', index='end', iid=idx, text='', values=(name, password))

            style = ttk.Style()
            style.configure("Treeview.Heading", font=('Arial', 12, 'bold'), foreground="Blue")
            tree.pack(expand=True, fill='both')

            def filter_tree():
                query = search_Var.get().capitalize()
                found = False
                for item in tree.get_children():
                    if query in tree.item(item, 'values')[0].capitalize():
                        tree.item(item, open=True)
                        tree.selection_set(item)
                        found = True
                    else:
                        tree.selection_remove(item)
                if not found and query:
                    messagebox.showinfo("Password Does Not Exist", f"No password found for '{query}'.")

            def delayed_filter():
                if hasattr(list_win, 'after_id'):
                    list_win.after_cancel(list_win.after_id)
                list_win.after_id = list_win.after(800, filter_tree)  

        else:
            messagebox.showinfo("Passwords", "Empty List !!")

    def delete():
        # accepting input from the user
        username = entryName.get().capitalize()

        # Check if app name exist
        user_found = False

        # creating a temporary list to store the data
        temp_passwords = []

        # reading data from the file and excluding the specified username
        try:
            with open("passwords.txt", 'r') as f:
                for k in f:
                    i = k.split(' ')
                    if i[0] != username:
                        temp_passwords.append(f"{i[0]} {i[1]}")
                    else:
                        user_found = True # Set true once data is read
            
            if user_found and len(username) != 0:

            #Ask for confirmation from the user 
                confirm = messagebox.askyesno("Confirm Delete", 
                                              f"Are you sure you want to delete the password for {username}?")
                
                if confirm:
                # writing the modified data back to the file
                    with open("passwords.txt", 'w') as f:
                        for line in temp_passwords:
                            f.write(line)
                    messagebox.showinfo(
                    "Success", f"App: {username} deleted successfully!")
                else:
                    messagebox.showinfo(
                    "Cancelled", f"The password for {username} still remains!")
            elif len(username) == 0:
                messagebox.showerror("Error", f"Please fill in the field: 'App Name'")
            else:
                 messagebox.showerror("Error", f"App: {username} does not exist!")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error deleting app {username}: {e}")

    def show_password():
        if entryPassword.cget('show') == '*':
            entryPassword.config(show='')
        else:
            entryPassword.config(show='*')
    
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

    # Add/Update button
    buttonAdd = Button(app, text="Add/Update", command=add_Or_Update)
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

    # Show Password button
    togglePassword = Checkbutton(app, text='Show Password', command=show_password)
    togglePassword.grid(row=1, column=2, padx=12, pady=5)




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

# Initializer

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

# Checks whether it is a first-time user

try:
    for run in range(len(code)):
        if words[run] == code[run]:
            verify += 1
except:
    verify = 0
        
if verify == len("@4tBp:>s#&^"):

    # Password box
    
    win.title("PassManager")
    Label(win, text = "   Enter password to have access to the program   ", fg = "red").grid(row = 0, columnspan = 2, pady = 2)
    Label(win, text = "Password:").grid(row = 2, sticky = E, pady = 6)
    passw = Entry(win, show = "*")
    passw.grid(row = 2, column = 1, sticky = W)
    
    # Check button
    
    equal = Button(win, text = "Submit", width = 10, bg = "red")
    equal.bind("<Button-1>", checkpassword)
    equal.grid(row = 3,column = 1, sticky = W)

else:   
    
    # Formatting middle screen
    
    win.geometry("+{}+{}".format(positionRight, positionDown))
    win.title("Setup")
    
    # New user text prompt
    
    Label(win, text = "Looks like you are a new user", fg = "red", font = ("ariel", 12)).grid(row = 0)
    Label(win, text = "Create a password below so that you can use the program successfully everytime you login").grid(row = 1, pady = 15)
    
    # Password box and entry
    
    Label(win, text = " New Password").grid(row = 2, padx = 20, sticky = W)
    passw1 = Entry(win, width = 40, show = "*")
    passw1.grid(row = 2, padx = 110, sticky = W)
    
    Label(win, text = " Confirm Password").grid(row = 3, sticky = W)
    passw2 = Entry(win, width = 40, show = "*")
    passw2.grid(row = 3, pady = 5, padx = 110, sticky = W) 
    
    # Proceed button
    
    proceed = Button(win, text = "Proceed>", width = 10)
    proceed.bind("<Button-1>", match)
    proceed.grid(row = 4, pady = 10)



win.mainloop()