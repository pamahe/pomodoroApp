from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLineEdit,
    QPushButton
)

from pathlib import Path
import sqlite3
import configparser
import hashlib


USER = None
DB = Path(__file__).parent / 'data' / 'database.db'


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.loginWindow = None
        self.setWindowTitle("Pomodoro App")
        self.setup_database()
        self.get_logged_user()

    @staticmethod
    def setup_database():
        DB.touch(mode=0o640, exist_ok=True)
        conn = sqlite3.connect(DB)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS users
        (
        	username text,
        	password text
        )
        """)
        conn.commit()
        conn.close()

    def get_logged_user(self):
        if not USER:
            self.loginWindow = LoginWindow()
            self.loginWindow.show()
            self.loginWindow.activateWindow()


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.signupWindow = None
        self.setWindowTitle("Login")
        self.setup_ui()
        self.setup_connexions()

    def setup_ui(self):
        self.layout = QVBoxLayout(self)
        self.le_username = QLineEdit(placeholderText="username")
        self.le_password = QLineEdit(placeholderText="password", echoMode=QLineEdit.EchoMode.Password)
        self.btn_login = QPushButton(text="Log In")
        self.btn_signup = QPushButton(text="Sign Up")

        self.layout.addWidget(self.le_username)
        self.layout.addWidget(self.le_password)
        self.layout.addWidget(self.btn_login)
        self.layout.addWidget(self.btn_signup)

    def setup_connexions(self):
        self.btn_login.clicked.connect(self.login)
        self.btn_signup.clicked.connect(self.signup)

    def login(self):
        pass

    def signup(self):
        self.signupWindow = SignUpWindow()
        self.signupWindow.show()
        self.signupWindow.activateWindow()


class SignUpWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sign Up")
        self.setup_ui()
        self.setup_connexions()

    def setup_ui(self):
        self.layout = QVBoxLayout(self)
        self.le_username = QLineEdit(placeholderText="username")
        self.le_password = QLineEdit(placeholderText="password", echoMode=QLineEdit.EchoMode.Password)
        self.le_confirmPassword = QLineEdit(placeholderText="confirm password", echoMode=QLineEdit.EchoMode.Password)
        self.btn_createAccount = QPushButton(text="Create Account")

        self.layout.addWidget(self.le_username)
        self.layout.addWidget(self.le_password)
        self.layout.addWidget(self.le_confirmPassword)
        self.layout.addWidget(self.btn_createAccount)

    def setup_connexions(self):
        self.btn_createAccount.clicked.connect(self.create_account)

    def create_account(self):
        username = self.le_username.text()
        if self.le_password.text() != self.le_confirmPassword.text():
            raise ValueError("Passwords don't match")
        password = self.le_password.text()

        # Verify that username is available
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT username from users")
        users = c.fetchall()
        print(users)
        conn.commit()
        conn.close()
        if username in [t[0] for t in users]:
            raise ValueError("Username not available")

        # hash password
        hash = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        d = {'username': username, 'hash': hash}
        c.execute("INSERT INTO users VALUES (:username, :hash)", d)
        conn.commit()
        conn.close()

        self.hide()


def start_app():
    app = QApplication()
    win = MainWindow()
    win.show()
    app.exec()


if __name__ == "__main__":
    start_app()
