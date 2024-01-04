from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QGridLayout,
    QLineEdit,
    QPushButton,
    QLCDNumber,
    QProgressBar,
    QCheckBox,
    QLabel
)
from PySide6.QtCore import QEvent

from pathlib import Path
import sqlite3
import configparser
import hashlib


USER = None
DB = Path(__file__).parent / 'data' / 'database.db'
CONFIG = Path(__file__).parent / 'data' / 'config.ini'


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.loginWindow = None
        self.setWindowTitle("Pomodoro App")
        self.window_drawn = False
        self.layout = QGridLayout(self)
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
        );
        """)
        conn.commit()
        conn.close()

    def event(self, event):
        if event.type() == QEvent.WindowActivate:
            if USER and not self.window_drawn:
                self.window_drawn = True
                self.setup()
        return super().event(event)

    def redraw_window(self):
        self.clear_layout()
        self.setup()

    def get_logged_user(self):
        global USER
        if not USER:
            self.loginWindow = LoginWindow(self)
            self.loginWindow.show()
            self.loginWindow.activateWindow()
        return True

    def setup(self):
        self.setup_ui()
        self.setup_connexions()
        self.update()

    def setup_config(self):
        config = configparser.ConfigParser()
        config.read(CONFIG)
        return config

    def setup_ui(self):
        config = self.setup_config()

        self.lcd_remainingTime = QLCDNumber()
        self.pb_sessionProgress = QProgressBar()
        self.btn_pause = QPushButton(text="Pause")
        self.btn_settings = QPushButton(text="Settings")
        self.btn_history = QPushButton(text="History")
        self.btn_logout = QPushButton(text="Log Out")

        if not USER:
            dailypomodorosessions = int(config['DEFAULT']['dailypomodorosessions'])
            pomodorosessionssprint = int(config['DEFAULT']['pomodorosessionssprint'])
        else:
            dailypomodorosessions = int(config[f'{USER.upper()}']['dailypomodorosessions'])
            pomodorosessionssprint = int(config[f'{USER.upper()}']['pomodorosessionssprint'])

        if dailypomodorosessions >= 16:
            lcd_height = ((dailypomodorosessions // pomodorosessionssprint) +
                          (dailypomodorosessions % pomodorosessionssprint))
        else:
            lcd_height = 4

        if pomodorosessionssprint >= 4:
            third_width = pomodorosessionssprint
        else:
            third_width = 4

        self.layout.addWidget(self.lcd_remainingTime, 1, 1, lcd_height, 2 * third_width - 1)
        self.layout.addWidget(self.pb_sessionProgress, 2 + lcd_height, 1, 1, 2 * third_width - 2)
        self.layout.addWidget(self.btn_pause, 2 + lcd_height, 1 + 2 * third_width - 2, 1, 1)
        self.layout.addWidget(self.btn_settings, 3 + lcd_height, 1, 1, third_width)
        self.layout.addWidget(self.btn_history, 3 + lcd_height, 1 + third_width, 1, third_width)
        self.layout.addWidget(self.btn_logout, 3 + lcd_height, 2 + 2 * third_width, 1, third_width)
        # Organize the sessions grid on the right
        sessions_checkboxes = []
        for row in range(dailypomodorosessions // third_width):
            for col in range(third_width):
                checkbox = QCheckBox()
                self.layout.addWidget(checkbox, 1 + row, 2 * third_width + 2 + col, 1, 1)
                sessions_checkboxes.append(checkbox)
        for rest in range(dailypomodorosessions % third_width):
            checkbox = QCheckBox()
            self.layout.addWidget(checkbox, 1 + dailypomodorosessions // third_width,
                                  2 * third_width + 2 + rest, 1, 1)
            sessions_checkboxes.append(checkbox)

    def setup_connexions(self):
        self.btn_pause.clicked.connect(self.pause)
        self.btn_settings.clicked.connect(self.goto_settings)
        self.btn_history.clicked.connect(self.goto_history)
        self.btn_logout.clicked.connect(self.logout)

    def pause(self):
        pass

    def goto_settings(self):
        self.SettingWindow = SettingsWindow(self)
        self.SettingWindow.show()
        self.SettingWindow.activateWindow()

    def goto_history(self):
        pass

    def logout(self):
        pass

    def clear_layout(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()


class LoginWindow(QWidget):
    def __init__(self, caller: MainWindow):
        super().__init__()
        self.caller = caller
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
        global USER
        username = self.le_username.text()
        password = hashlib.sha256(self.le_password.text().encode()).hexdigest()

        # Get user from database
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        d = {'username': username, 'hash': password}
        c.execute("SELECT count(*) FROM users WHERE username=:username and password=:hash;", d)
        result = c.fetchone()
        conn.commit()
        conn.close()

        if result[0] == 0:
            raise ValueError("Account not found")

        USER = username
        self.hide()
        self.caller.update()
        return True

    def signup(self):
        self.signupWindow = SignUpWindow(self)
        self.signupWindow.show()
        self.signupWindow.activateWindow()


class SignUpWindow(QWidget):
    def __init__(self, caller: LoginWindow):
        super().__init__()
        self.caller = caller
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
        conn.commit()
        conn.close()
        if username in [t[0] for t in users]:
            raise ValueError("Username not available")

        # hash password
        hash = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        d = {'username': username, 'hash': hash}
        c.execute("INSERT INTO users VALUES (:username, :hash);", d)
        conn.commit()
        conn.close()

        self.create_user_config(username)

        self.hide()
        self.caller.update()
        return True

    def create_user_config(self, username):
        with (open(CONFIG, 'a') as f):
            config_lines = [
                f"[{username.upper()}]\n", "dailypomodorosessions = 8\n", "pomodorosessionssprint = 4\n",
                "pomodorosessionduration = 25\n", "smallbreakduration = 5\n", "bigbreakduration = 30\n"]
            for line in config_lines:
                f.write(line)
        return None


class SettingsWindow(QWidget):
    def __init__(self, caller: MainWindow):
        super().__init__()
        self.caller = caller
        self.setWindowTitle("Settings")
        self.setup_ui()
        self.setup_connexions()

    def setup_ui(self):
        global USER
        self.layout = QGridLayout(self)

        self.qte_dps = QLabel(text="Daily Pomodoro Sessions")
        self.qte_pss = QLabel(text="Pomodoro Sessions Sprint")
        self.qte_psd = QLabel(text="Pomodoro Session Duration (min)")
        self.qte_smd = QLabel(text="Sessions Break Duration (min)")
        self.qte_bbd = QLabel(text="Sprint Break Duration (min)")

        config = self.caller.setup_config()
        self.le_dps = QLineEdit()
        self.le_pss = QLineEdit()
        self.le_psd = QLineEdit()
        self.le_smd = QLineEdit()
        self.le_bbd = QLineEdit()
        self.le_dps.setText(config[USER.upper()]["dailypomodorosessions"])
        self.le_pss.setText(config[USER.upper()]["pomodorosessionssprint"])
        self.le_psd.setText(config[USER.upper()]["pomodorosessionduration"])
        self.le_smd.setText(config[USER.upper()]["smallbreakduration"])
        self.le_bbd.setText(config[USER.upper()]["bigbreakduration"])

        self.layout.addWidget(self.qte_dps, 1, 1)
        self.layout.addWidget(self.qte_pss, 2, 1)
        self.layout.addWidget(self.qte_psd, 3, 1)
        self.layout.addWidget(self.qte_smd, 4, 1)
        self.layout.addWidget(self.qte_bbd, 5, 1)
        self.layout.addWidget(self.le_dps, 1, 2)
        self.layout.addWidget(self.le_pss, 2, 2)
        self.layout.addWidget(self.le_psd, 3, 2)
        self.layout.addWidget(self.le_smd, 4, 2)
        self.layout.addWidget(self.le_bbd, 5, 2)

        self.btn_savesettings = QPushButton(text="Save Settings")
        self.layout.addWidget(self.btn_savesettings, 6, 1)

    def setup_connexions(self):
        self.btn_savesettings.clicked.connect(self.save_settings)

    def save_settings(self):
        config = self.caller.setup_config()
        config.set(f"{USER.upper()}", "dailypomodorosessions", self.le_dps.text())
        config.set(f"{USER.upper()}", "pomodorosessionssprint", self.le_pss.text())
        config.set(f"{USER.upper()}", "pomodorosessionduration", self.le_psd.text())
        config.set(f"{USER.upper()}", "smallbreakduration", self.le_smd.text())
        config.set(f"{USER.upper()}", "bigbreakduration", self.le_bbd.text())
        with open(CONFIG, 'w') as configfile:
            config.write(configfile)
        self.hide()
        self.caller.redraw_window()


def start_app():
    app = QApplication()
    win = MainWindow()
    win.show()
    app.exec()


if __name__ == "__main__":
    start_app()
