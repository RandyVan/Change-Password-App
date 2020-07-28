- Before running the program ensure to change the values of user and passwd on lines 20,21 in the beginning of the program and on 
lines 260, and 261 in the update function to your personal SQL user and password.

- If your SQL user login is "root" then change user(line 22,260) to "root", if your SQL password is "Dog" change passwd(line 23,261) to "Dog".
- The program would not successfully run and the database would not be created if the above steps arent' followed.

- After the user and passwd has been changed in the fields mentioned above:
- The GUI should appear. Below are the listed default userid and passwords. Use them to prevent a userid not found error

     userid                  current password     
  1. ljames23@gmail.com      Strive4greatness1!
  2. mjordan23@gmail.com     Belikemike1!
  3. kbryant24@gmail.com     Mambamentality1!
  4. scurry30@gmail.com      Chefcurry1!
  5. jharden13@gmail.com     Fearthebeard1!

- Here are the list of old passwords for each user. The order is from oldest to newest password. The first password is the oldest
and the 5th password is the most current among the old password. The use of any of these passwords would throw a reuse password error.

Strive4greatness2!,Strive4greatness3!,Strive4greatness4!,Strive4greatness5!,Strive4greatness6!
Belikemike2!,Belikemike3!,Belikemike4!,Belikemike5!,Belikemike6!
Mambamentality2!,Mambamentality3!,Mambamentality4!,Mambamentality5!,Mambamentality6!
Chefcurry2!,Chefcurry3!,Chefcurry4!,Chefcurry5!,Chefcurry6!
Fearthebeard2!,Fearthebeard3!,Fearthebeard4!,Fearthebeard5!,Fearthebeard6!

- All current and old passwords are encrypted with the AES function. 
To decrypt the function and view the passwords in the database in plaintext the decrypt()function would be used.

The following SQL statement would be used to view the unencrypted passwords in the user_randy table:
SELECT userid,first_name,last_name,aes_decrypt(current_password,'key') FROM randy_user;

To view the table in plaintext for the randy_password_history table:
SELECT oldpassid,userid,aes_decrypt(oldpassword,'key'),date FROM randy_password_history;


** To save you the time from retesting my program for this particular requirement.

I was unable to update the database to replace the current/oldpassword to replace with the oldest password
in the password history table. MYSQL doesn't allow the use of an UPDATE/DELETE in conjuction with a subquery
and a min() or order by limit 1 statement.I tried everything but all the methods I tried gave me errors or completely 
broke my program. The rest of the program should work fine and meet the rest of the requirements.