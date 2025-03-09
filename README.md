# ADVANCED-ENCRYPTION-TOOL
*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: PANKAJ MENARIA

*INTERN ID*: CT08SOJ

*DOMAIN*: CYBER SECURITY AND ETHICAL HACKING

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

#This project is a GUI-based AES-256 encryption and decryption tool built using PyQt5 for the interface and PyCryptodome for cryptographic operations. The application allows users to securely encrypt and decrypt files with AES-256 encryption in CBC (Cipher Block Chaining) mode.
#Key Features:
Password-Based Encryption and Decryption:

The tool uses AES-256 encryption, where a password entered by the user is hashed using SHA-256 to generate a 256-bit key for encryption and decryption.
File Selection:

Users can select any file they wish to encrypt or decrypt via a file dialog.
Encryption Process:

When the user selects a file to encrypt, the tool generates a random initialization vector (IV), which is needed for CBC mode encryption.
The file content is then encrypted using the password-provided key and the IV.
The encrypted file is saved with a .enc extension.
Decryption Process:

For decryption, the tool prompts the user to enter the password again. It reads the IV and ciphertext from the .enc file and attempts to decrypt it using the same password.
The decrypted file is saved with a .dec extension.
Error Handling:

The application includes error handling for empty password fields and incorrect password entries during decryption. If decryption fails due to an incorrect password or corrupted file, the user is notified with an error message.
Graphical User Interface (GUI):

The application uses a simple and user-friendly interface built with PyQt5:
Password Input Field: A secure text field to enter the password for encryption and decryption.
Buttons: Two main buttons for encrypting and decrypting files.

#OUTPUT
![Image](https://github.com/user-attachments/assets/78d864bb-c4bf-43b9-8cea-2b8133b51aa3)

