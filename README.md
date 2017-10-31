# FuseOS

An encrypted filesystem using FUSE in Python.
All writes are encrypted and all reads are decrypted.

A random string of 30 characters is generated initially. This is the passphrase.
Passphrase is used to encrypt the files.

The passphrase is in turn encrypted using the user's password. This is stored in "encry.txt".

The user password is hashed and stored in "key.txt".

An option to change password is provided each time the program starts.

The passphrase helps when we have to change the password. If passphrase is not used, all the files in the filesystem would have to be rewritten by encrypting with it with the new password.
This would cause a lot of overhead while changing the password. Hence a passphrase, which doesn't change, is used to encrypt the files.


Note: While testing this program, please create two empty files, in the same folder as the program, namely "key.txt" and "encry.txt".
I will try to automate this process in the next version of the code.

Don't run the code in background unless you know how to kill it manually. You might have to restart your system to unmount if you aren't sure about killing the process.
