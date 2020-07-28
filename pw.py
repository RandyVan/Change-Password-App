import mysql.connector
import datetime
from tkinter import *
from tkinter import messagebox
import os
import re

# Creates Window
Window = Tk()
Window.geometry('700x200+700+250')
Window.title('Change Password')

username = StringVar() # creates string variable for username entered
curr_pass = StringVar() #creates string variable for current password entered
pw1 = StringVar() # creates string variable for password
pw2 = StringVar() # creates string variable for confirmation password

db = mysql.connector.connect(
    host = "localhost",
    user = "root", # replace value for personal SQL username
    passwd = "nash13" #replace value for personal SQL password
    #database = "dbsec"
)
cursor = db.cursor()

cursor.execute("CREATE DATABASE IF NOT EXISTS dbsec")
cursor.execute("USE dbsec")
cursor.execute("""CREATE TABLE IF NOT EXISTS randy_user(
Userid varchar(50) PRIMARY KEY NOT NULL,
First_name varchar(25) NOT NULL,
Last_name varchar(25) NOT NULL,
Current_password varbinary(150) NOT NULL
)""")

cursor.execute("""CREATE TABLE IF NOT EXISTS randy_password_history(
OldpassID INT,
Oldpassword varbinary(150) PRIMARY KEY,
UserID varchar(50) NOT NULL,
Date Date NOT NULL,
FOREIGN KEY (Userid) REFERENCES randy_user(Userid)
)""")

cursor.execute("""INSERT IGNORE INTO randy_user (Userid,First_name,Last_name,Current_password) VALUES
(%s,%s,%s,aes_encrypt(%s,'key'))""",("ljames23@gmail.com","Lebron","James","Strive4greatness1!"))
cursor.execute("""INSERT IGNORE INTO randy_user (Userid,First_name,Last_name,Current_password) VALUES
(%s,%s,%s,aes_encrypt(%s,'key'))""",("mjordan23@gmail.com","Michael","Jordan","Belikemike1!"))
cursor.execute("""INSERT IGNORE INTO randy_user (Userid,First_name,Last_name,Current_password) VALUES
(%s,%s,%s,aes_encrypt(%s,'key'))""",("kbryant24@gmail.com","Kobe","Bryant","Mambamentality1!"))
cursor.execute("""INSERT IGNORE INTO randy_user (Userid,First_name,Last_name,Current_password) VALUES
(%s,%s,%s,aes_encrypt(%s,'key'))""",("scurry30@gmail.com","Stephen","Curry","Chefcurry1!"))
cursor.execute("""INSERT IGNORE INTO randy_user (Userid,First_name,Last_name,Current_password) VALUES
(%s,%s,%s,aes_encrypt(%s,'key'))""",("jharden13@gmail.com","James","Harden","Fearthebeard1!"))

cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(1,"Strive4greatness2!", "ljames23@gmail.com", "2019-05-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(2,"Strive4greatness3!", "ljames23@gmail.com", "2019-06-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(3,"Strive4greatness4!", "ljames23@gmail.com", "2019-07-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(4,"Strive4greatness5!", "ljames23@gmail.com", "2019-08-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(5,"Strive4greatness6!", "ljames23@gmail.com", "2019-09-20"))

cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(1,"Belikemike2!", "mjordan23@gmail.com", "2019-05-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(2,"Belikemike3!", "mjordan23@gmail.com", "2019-06-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(3,"Belikemike4!", "mjordan23@gmail.com", "2019-07-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(4,"Belikemike5!", "mjordan23@gmail.com", "2019-08-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(5,"Belikemike6!", "mjordan23@gmail.com", "2019-09-20"))

cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(1,"Mambamentality2!", "kbryant24@gmail.com", "2019-05-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(2,"Mambamentality3!", "kbryant24@gmail.com", "2019-06-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(3,"Mambamentality4!", "kbryant24@gmail.com", "2019-07-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(4,"Mambamentality5!", "kbryant24@gmail.com", "2019-08-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(5,"Mambamentality6!", "kbryant24@gmail.com", "2019-09-20"))

cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(1,"Chefcurry2!", "scurry30@gmail.com", "2019-05-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(2,"Chefcurry3!", "scurry30@gmail.com", "2019-06-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(3,"Chefcurry4!", "scurry30@gmail.com", "2019-07-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(4,"Chefcurry5!", "scurry30@gmail.com", "2019-08-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(5,"Chefcurry6!", "scurry30@gmail.com", "2019-09-20"))

cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(1,"Fearthebeard2!", "jharden13@gmail.com", "2019-05-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(2,"Fearthebeard3!", "jharden13@gmail.com", "2019-06-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(3,"Fearthebeard4!", "jharden13@gmail.com", "2019-07-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(4,"Fearthebeard5!", "jharden13@gmail.com", "2019-08-20"))
cursor.execute("""INSERT IGNORE INTO randy_password_history (OldpassID,oldpassword,UserID,Date) VALUES
(%s,aes_encrypt(%s,'key'),%s, %s)""",(5,"Fearthebeard6!", "jharden13@gmail.com", "2019-09-20"))

db.commit() 

#Function that clears the results textbox
def clear_results(event):
    result_entry.delete(0,"end")
    return None     


# Creates labels and entries for username 
username_label = Label(Window, text="Please Enter your UserID:   ")
username_label.grid(row=0, column=0)
username_entry = Entry(Window, textvariable = username)
username_entry.grid(row=0, column=1)
username_entry.bind("<Key>",clear_results)# On  press, clears results textbox

# Creates labels and entries for current password
currPass_label = Label(Window, text="Please Enter your current password:   ")
currPass_label.grid(row=1, column=0)
currPass_entry = Entry(Window, textvariable = curr_pass, show='*')
currPass_entry.grid(row=1, column=1)
currPass_entry.bind("<Key>",clear_results)# On  press, clears results textbox

# Creates labels and entries for new password entry 1.
pw_label1 = Label(Window, text="Please Enter your new password: ")
pw_label1.grid(row=2, column=0)
pw_entry1 = Entry(Window, textvariable = pw1, show="*") # hides password
pw_entry1.grid(row=2, column=1)
pw_entry1.bind("<Key>",clear_results)

# Creates labels and entries for pw2 for password confirmation.
pw_label2 = Label(Window, text="Please Confirm your new password: ")
pw_label2.grid(row=3, column=0)
pw_entry2 = Entry(Window, textvariable = pw2, show="*")
pw_entry2.grid(row=3, column=1)
pw_entry2.bind("<Key>",clear_results)

un_entry = username.get() # stores username entry
currPass1_entry = curr_pass.get() #stores current password from user
pw1_entry = pw1.get() # stores new input password from user.
pw2_entry = pw2.get() # stores new input confirmation password

# Throw error if fields are empty
def check_fields():

    un_entry = username.get() # stores username entry
    currPass1_entry = curr_pass.get() #stores current password from user
    pw1_entry = pw1.get() # stores new input password from user.
    pw2_entry = pw2.get() # stores new input confirmation password

    if Window.winfo_exists():
        if len(pw1_entry) == 0 or len(pw2_entry) == 0 or len(un_entry) == 0 or len(currPass1_entry) == 0:
            messagebox.showerror("Error","Please Fill In All Data Fields!")
        else:
            check_user()

# checks if userid is a valid email
def check_user():
 
    email = re.compile('[a-z0-9]+[@]\w+[.]\w{2,3}$') # valis email using regex
    un_entry = username.get() # stores the user input for username.

    if(re.search(email,un_entry)): #checks for valid email
        check_password()
    else:
        messagebox.showerror("Error","UserID must be a valid email address")

# function that checks if the password meets all conditions.
def check_password():
  
    un_entry = username.get() # stores username entry
    currPass1_entry = curr_pass.get() #stores current password from user
    pw1_entry = pw1.get() # stores new input password from user.
    pw2_entry = pw2.get() # stores new input confirmation password
    upper_case = re.compile('[A-Z]+') # uses regex to search for uppercase character
    lower_case = re.compile('[a-z]{2,}') # uses regex to search for 2 lowercase letters
    special_char = re.compile('[^A-Za-z0-9]') # uses regex to search for special character
    digit = re.compile('\d') # uses regex to search for digit
    count = 5 # a count to 5, if count remains 5, password meets all conditions.
    req_met = 2

    cursor.execute("SELECT userid FROM randy_user") #Selects userid from randy_user table
    users= cursor.fetchall() # stores all fetched data from query into users variable
    users=[i[0] for i in users] # converts list of tuples into list of strings

    cursor.execute("SELECT aes_decrypt(current_password,'key') FROM randy_user") # selects current password from randy_user table
    cpass= cursor.fetchall() # stores all fetched data from query into users variable
    cpass=[i[0] for i in cpass] # converts list of tuples into list of strings
    credentials = dict(zip(users,cpass)) # converts list into dictionary. UserID is key and current password is value.

    cursor.execute("""SELECT userid,aes_decrypt(oldpassword,'key') from randy_password_history""") #selects userid & oldpasswords from randy_password_history
    old_pass= cursor.fetchall() #stores query into variable old_pass
    dict_old_pass = dict() 
    #converts data into a dictionary 
    for UserID,oldpasswords in old_pass:
        dict_old_pass.setdefault(UserID,[]).append(oldpasswords)
    final_old_pass = {k:(','.join(v)) for k,v in dict_old_pass.items()} #converts dictionary values from list to strings.
                
    # checks if the inputted user is in the database, returns error if user doesn't exist
    if un_entry.lower() not in (users):
        messagebox.showerror("Error","UserID does not exist!")

    # checks if current password entry matches the correct username key and associated password value.
    if currPass1_entry == credentials.get(un_entry.lower()): 
        if pw1_entry == pw2_entry: # Test if password matches confirmation password
            if (pw1_entry and pw2_entry) in (final_old_pass.get(un_entry).split(',')):
                result_entry.insert(END,pw1_entry + " - Password cannot match last 5 passwords") 
                req_met -= 1
            
            if currPass1_entry == pw1_entry and pw2_entry:
                result_entry.insert(END, "Cannot reuse current password!")
                req_met -= 1

            if len(pw1_entry) & len(pw2_entry) < 10:
                result_entry.insert(END,pw1_entry + " - Password should be at least 10 characters")
                count -= 1 # if condition is met, count remains the same

            # checks for at least one uppercase letter
            elif(upper_case.search(pw1_entry) == None):
                result_entry.insert(END,pw1_entry + " - Password must contain at least one uppercase letter")
                count -= 1

            # checks for at least two lowercase letter
            elif(lower_case.search(pw1_entry) == None):
                result_entry.insert(END, pw1_entry + " - Password must contain at least two lowercase letter") 
                count -= 1

            # checks for special character
            elif(special_char.search(pw1_entry) == None ):
                result_entry.insert(END, pw1_entry + " - Password must contain special character")
                count -= 1

            # checks for at least one digit
            elif(digit.search(pw1_entry) == None):
                result_entry.insert(END, pw1_entry + " - Password must contain at least one digit")
                count -= 1

            # checks to see if all conditions are met
            elif req_met == 2 and count == 5:
                update()
                result_entry.insert(END,"Password Changed")
            # prints if password doesn't match
        else:
            result_entry.insert(END,"Error! Password Doesn't Match") 
    else:
        messagebox.showerror("Error","Invalid Password!")


def update():

    db = mysql.connector.connect(
    host = "localhost",
    user = "root", # replace value for personal SQL username
    passwd = "nash13" #replace value for personal SQL password
    )
    
    cursor = db.cursor()
    cursor.execute("Use dbsec")
    un_entry = username.get() # stores username entry
    currPass1_entry = curr_pass.get() #stores current password from user
    pw1_entry = pw1.get() # stores new input password from user.
    pw2_entry = pw2.get() # stores new input confirmation password 
    up_pass = cursor.execute("UPDATE randy_user SET current_password= aes_encrypt(%s,'key') WHERE userid=%s",(pw1_entry,un_entry))
    cursor.execute(up_pass)
   
           
    db.commit()


# Creates validation button
checkStrBtn = Button(Window, text="Change Password", command=check_fields, height=2, width=20)
checkStrBtn.grid(row=4, column=1)

# creates results label and textbox entry
result_label = Label(Window, text="Result: ")
result_label.grid(row=5, column=0)
result_entry = Entry(Window, width= 30)
result_entry.grid(row=5, column=1)  

Window.mainloop()
