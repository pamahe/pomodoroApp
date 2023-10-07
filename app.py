from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLineEdit,
    QPushButton
)

USER = None


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.loginWindow = None
        self.setWindowTitle("Pomodoro App")
        self.get_logged_user()

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
        self.btn_createAccount.clicked.connect(self.createAccount)

    def createAccount(self):
        # TODO : new user logic
        self.hide()


def start_app():
    app = QApplication()
    win = MainWindow()
    win.show()
    app.exec()


if __name__ == "__main__":
    start_app()