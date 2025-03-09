import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel, QLineEdit, QMessageBox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

class EncryptionTool(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("AES-256 Encryption Tool")
        self.setGeometry(300, 300, 400, 200)

        # Set black background
        self.setStyleSheet("background-color: black; color: white;")

        layout = QVBoxLayout()

        # Password label
        self.label = QLabel("Enter Password:", self)
        self.label.setStyleSheet("color: white; font-size: 14px;")
        layout.addWidget(self.label)

        # Password input field
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("""
            background-color: #333;
            color: white;
            border: 1px solid #666;
            padding: 5px;
            font-size: 14px;
        """)
        layout.addWidget(self.password_input)

        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt File", self)
        self.encrypt_button.setStyleSheet("""
            background-color: #444;
            color: white;
            font-size: 14px;
            padding: 10px;
            border-radius: 5px;
        """)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt File", self)
        self.decrypt_button.setStyleSheet("""
            background-color: #444;
            color: white;
            font-size: 14px;
            padding: 10px;
            border-radius: 5px;
        """)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.setLayout(layout)

    def get_key(self, password):
        return hashlib.sha256(password.encode()).digest()

    def encrypt_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt", "", "All Files (*)", options=options)
        
        if not file_path:
            return

        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Password cannot be empty!")
            return

        key = self.get_key(password)
        iv = os.urandom(16)

        with open(file_path, "rb") as f:
            plaintext = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as f:
            f.write(iv + ciphertext)

        QMessageBox.information(self, "Success", f"File encrypted and saved as: {encrypted_file_path}")

    def decrypt_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
        
        if not file_path:
            return

        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Password cannot be empty!")
            return

        key = self.get_key(password)

        with open(file_path, "rb") as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError:
            QMessageBox.warning(self, "Error", "Incorrect password or corrupted file!")
            return

        decrypted_file_path = file_path.replace(".enc", ".dec")
        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)

        QMessageBox.information(self, "Success", f"File decrypted and saved as: {decrypted_file_path}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EncryptionTool()
    window.show()
    sys.exit(app.exec_())

