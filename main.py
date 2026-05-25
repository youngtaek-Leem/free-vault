import sys
import string
import secrets

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QFrame, QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QDialog, QMessageBox,
)
from PyQt6.QtCore import Qt

from security import SecurityManager
from database import DatabaseManager
from ui_components import DarkStyle


class PasswordManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Connect Vault - Secure Password Manager")
        self.resize(900, 600)
        self.setStyleSheet(DarkStyle.SHEET)

        self.sec = SecurityManager()
        self.db = DatabaseManager()

        if not self.db.is_configured():
            self.init_supabase_setup_ui()
        elif not self.db.restore_session():
            self.init_cloud_auth_ui()
        else:
            self.init_auth_ui()

    # ── 공통 헬퍼 ─────────────────────────────────────────────────────────────

    def _set_centered_widget(self, inner: QWidget):
        container = QWidget()
        self.setCentralWidget(container)
        lay = QVBoxLayout(container)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(inner)

    def _make_panel(self, width: int = 420) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setFixedWidth(width)
        frame.setStyleSheet(
            f"background:{DarkStyle.PANEL_BG};border-radius:15px;padding:20px;"
        )
        return frame, QVBoxLayout(frame)

    # ── 1단계: Supabase 설정 ─────────────────────────────────────────────────

    def init_supabase_setup_ui(self):
        frame, lay = self._make_panel()

        title = QLabel("Supabase 연결 설정")
        title.setStyleSheet("font-size:20px;font-weight:bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        desc = QLabel(
            "Supabase 프로젝트 URL과 Anon Key를 입력하세요.\n"
            "(설정은 ~/.connect_vault/supabase.json 에 저장됩니다)"
        )
        desc.setStyleSheet("color:#888;font-size:12px;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)

        self.sb_url_input = QLineEdit()
        self.sb_url_input.setPlaceholderText("https://your-project.supabase.co")

        self.sb_key_input = QLineEdit()
        self.sb_key_input.setPlaceholderText("Supabase Anon Key")

        connect_btn = QPushButton("연결")
        connect_btn.clicked.connect(self.handle_supabase_setup)

        for w in (title, desc, QLabel("Supabase URL"), self.sb_url_input,
                  QLabel("Anon Key"), self.sb_key_input, connect_btn):
            lay.addWidget(w)

        self._set_centered_widget(frame)

    def handle_supabase_setup(self):
        url = self.sb_url_input.text().strip()
        key = self.sb_key_input.text().strip()
        if not url or not key:
            QMessageBox.warning(self, "오류", "URL과 Key를 모두 입력하세요.")
            return
        try:
            self.db.configure(url, key)
            self.init_cloud_auth_ui()
        except Exception as e:
            QMessageBox.critical(self, "연결 실패", str(e))

    # ── 2단계: 클라우드 로그인 ───────────────────────────────────────────────

    def init_cloud_auth_ui(self):
        frame, lay = self._make_panel(400)

        title = QLabel("클라우드 로그인")
        title.setStyleSheet("font-size:20px;font-weight:bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("이메일")

        self.cloud_pw_input = QLineEdit()
        self.cloud_pw_input.setPlaceholderText("클라우드 계정 비밀번호")
        self.cloud_pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.cloud_pw_input.returnPressed.connect(self.handle_cloud_login)

        login_btn = QPushButton("로그인")
        login_btn.clicked.connect(self.handle_cloud_login)

        signup_btn = QPushButton("회원가입")
        signup_btn.setStyleSheet("background:#444;color:#aaa;")
        signup_btn.clicked.connect(self.handle_cloud_signup)

        settings_btn = QPushButton("Supabase 설정 변경")
        settings_btn.setStyleSheet("background:transparent;color:#666;border:none;")
        settings_btn.clicked.connect(self.init_supabase_setup_ui)

        for w in (title, QLabel("이메일"), self.email_input,
                  QLabel("비밀번호"), self.cloud_pw_input,
                  login_btn, signup_btn, settings_btn):
            lay.addWidget(w)

        self._set_centered_widget(frame)

    def handle_cloud_login(self):
        email = self.email_input.text().strip()
        password = self.cloud_pw_input.text()
        if not email or not password:
            QMessageBox.warning(self, "오류", "이메일과 비밀번호를 입력하세요.")
            return
        try:
            self.db.sign_in(email, password)
            self.init_auth_ui()
        except Exception as e:
            QMessageBox.critical(self, "로그인 실패", str(e))

    def handle_cloud_signup(self):
        email = self.email_input.text().strip()
        password = self.cloud_pw_input.text()
        if not email or not password:
            QMessageBox.warning(self, "오류", "이메일과 비밀번호를 입력하세요.")
            return
        try:
            self.db.sign_up(email, password)
            QMessageBox.information(self, "회원가입", "확인 이메일을 확인한 후 로그인하세요.")
        except Exception as e:
            QMessageBox.critical(self, "오류", str(e))

    # ── 3단계: 마스터 패스워드 ─────────────────────────────────────────────

    def init_auth_ui(self):
        frame, lay = self._make_panel(400)

        title = QLabel("Connect Vault")
        title.setStyleSheet("font-size:24px;font-weight:bold;margin-bottom:10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("마스터 패스워드 입력")
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_input.returnPressed.connect(self.handle_auth)

        login_btn = QPushButton("금고 열기")
        login_btn.clicked.connect(self.handle_auth)

        setup_btn = QPushButton("비밀번호 설정/변경")
        setup_btn.setStyleSheet("background:#444;color:#aaa;")
        setup_btn.clicked.connect(self.handle_setup_password)

        logout_btn = QPushButton("클라우드 로그아웃")
        logout_btn.setStyleSheet("background:transparent;color:#666;border:none;")
        logout_btn.clicked.connect(self.handle_cloud_logout)

        for w in (title, self.pw_input, login_btn, setup_btn, logout_btn):
            lay.addWidget(w)

        self._set_centered_widget(frame)

    def handle_auth(self):
        password = self.pw_input.text()
        if not password:
            QMessageBox.warning(self, "오류", "비밀번호를 입력하세요.")
            return

        try:
            salt, verify_token = self.db.get_vault_config()
        except Exception as e:
            QMessageBox.critical(self, "오류", f"서버 연결 실패: {e}")
            return

        if salt is None:
            QMessageBox.warning(self, "알림", "먼저 마스터 비밀번호를 설정해주세요.")
            return

        self.sec.derive_key(password, salt)
        if not self.sec.check_verify_token(verify_token):
            self.sec.key = None
            QMessageBox.critical(self, "인증 실패", "마스터 패스워드가 틀렸습니다.")
            return

        self.enter_vault()

    def handle_setup_password(self):
        password = self.pw_input.text()
        if not password:
            QMessageBox.warning(self, "오류", "설정할 비밀번호를 입력창에 먼저 입력하세요.")
            return

        reply = QMessageBox.question(
            self, "비밀번호 설정",
            "새로운 마스터 비밀번호를 설정합니다.\n"
            "이 작업 시 기존의 모든 저장 데이터는 삭제됩니다. 계속하시겠습니까?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self.db.clear_passwords()
            salt = SecurityManager.generate_salt()
            self.sec.derive_key(password, salt)
            verify = self.sec.make_verify_token()
            self.db.set_vault_config(salt, verify)
            QMessageBox.information(self, "완료", "비밀번호가 설정되었습니다.")
            self.enter_vault()
        except Exception as e:
            QMessageBox.critical(self, "오류", str(e))

    def handle_cloud_logout(self):
        self.db.sign_out()
        self.sec.key = None
        self.init_cloud_auth_ui()

    # ── 금고 화면 ────────────────────────────────────────────────────────────

    def enter_vault(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        main_layout = QHBoxLayout(self.central_widget)

        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("background:#181818;border-right:1px solid #333;")
        side_layout = QVBoxLayout(sidebar)

        add_btn = QPushButton("+ 항목 추가")
        add_btn.clicked.connect(self.show_add_dialog)

        gen_btn = QPushButton("비밀번호 생성기")
        gen_btn.clicked.connect(self.generate_random_pw)

        lock_btn = QPushButton("금고 잠그기")
        lock_btn.clicked.connect(lambda: (setattr(self.sec, "key", None), self.init_auth_ui()))

        side_layout.addWidget(add_btn)
        side_layout.addWidget(gen_btn)
        side_layout.addStretch()
        side_layout.addWidget(lock_btn)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["서비스", "사용자", "비밀번호", "작업"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.table)

        self.refresh_vault()

    def refresh_vault(self):
        self.table.setRowCount(0)
        try:
            entries = self.db.get_all_passwords()
        except Exception as e:
            QMessageBox.warning(self, "오류", f"데이터 로드 실패: {e}")
            return

        for row_idx, (entry_id, enc_svc, enc_usr, enc_pw) in enumerate(entries):
            self.table.insertRow(row_idx)

            try:
                service = self.sec.decrypt(enc_svc)
            except Exception as e:
                service = f"[복호화 오류: {e}]"

            try:
                username = self.sec.decrypt(enc_usr)
            except Exception as e:
                username = f"[복호화 오류: {e}]"

            try:
                dec_pw = self.sec.decrypt(enc_pw)
            except Exception as e:
                dec_pw = f"[복호화 오류: {e}]"

            self.table.setItem(row_idx, 0, QTableWidgetItem(service))
            self.table.setItem(row_idx, 1, QTableWidgetItem(username))

            pw_item = QTableWidgetItem("••••••••")
            pw_item.setData(Qt.ItemDataRole.UserRole, dec_pw)
            self.table.setItem(row_idx, 2, pw_item)

            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0, 0, 0, 0)
            action_layout.setSpacing(5)

            view_btn = QPushButton("보기")
            view_btn.setFixedWidth(50)
            view_btn.clicked.connect(
                lambda checked, r=row_idx: self.toggle_password_visibility(r)
            )

            del_btn = QPushButton("삭제")
            del_btn.setFixedWidth(50)
            del_btn.clicked.connect(
                lambda checked, eid=entry_id: self.delete_entry(eid)
            )

            action_layout.addWidget(view_btn)
            action_layout.addWidget(del_btn)
            self.table.setCellWidget(row_idx, 3, action_widget)

    def toggle_password_visibility(self, row):
        item = self.table.item(row, 2)
        real_pw = item.data(Qt.ItemDataRole.UserRole)
        item.setText(real_pw if item.text() == "••••••••" else "••••••••")

    def show_add_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("새 항목 추가")
        dialog.setFixedWidth(300)
        dialog.setStyleSheet(DarkStyle.SHEET)

        layout = QVBoxLayout(dialog)

        service_in = QLineEdit()
        service_in.setPlaceholderText("서비스 (예: Google)")
        user_in = QLineEdit()
        user_in.setPlaceholderText("사용자 ID")
        pw_in = QLineEdit()
        pw_in.setPlaceholderText("비밀번호")
        pw_in.setEchoMode(QLineEdit.EchoMode.Password)

        save_btn = QPushButton("저장")

        def save():
            if not service_in.text() or not pw_in.text():
                return
            try:
                enc_svc = self.sec.encrypt(service_in.text())
                enc_usr = self.sec.encrypt(user_in.text())
                enc_pw = self.sec.encrypt(pw_in.text())
                self.db.add_password(enc_svc, enc_usr, enc_pw)
                self.refresh_vault()
                dialog.accept()
            except Exception as e:
                QMessageBox.critical(dialog, "오류", str(e))

        save_btn.clicked.connect(save)

        layout.addWidget(QLabel("서비스"))
        layout.addWidget(service_in)
        layout.addWidget(QLabel("사용자 ID"))
        layout.addWidget(user_in)
        layout.addWidget(QLabel("비밀번호"))
        layout.addWidget(pw_in)
        layout.addWidget(save_btn)

        dialog.exec()

    def generate_random_pw(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        pw = "".join(secrets.choice(chars) for _ in range(16))
        QMessageBox.information(self, "생성된 비밀번호", f"추천 비밀번호:\n\n{pw}\n\n복사하여 사용하세요.")

    def delete_entry(self, entry_id):
        self.db.delete_password(entry_id)
        self.refresh_vault()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManagerApp()
    window.show()
    sys.exit(app.exec())
