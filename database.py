import json
import base64
from pathlib import Path

_CONFIG_DIR = Path.home() / ".connect_vault"
_CONFIG_FILE = _CONFIG_DIR / "supabase.json"
_SESSION_FILE = _CONFIG_DIR / "session.json"


class DatabaseManager:
    """
    Supabase 백엔드 — iCloud 불필요, 웹 앱과 동일한 테이블 공유.

    Supabase 테이블 (최초 한 번 대시보드에서 생성 필요):

        CREATE TABLE vault_config (
            id          BIGSERIAL PRIMARY KEY,
            user_id     UUID REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
            salt        TEXT NOT NULL,
            verify      TEXT NOT NULL,
            updated_at  TIMESTAMPTZ DEFAULT NOW()
        );
        ALTER TABLE vault_config ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "own config" ON vault_config FOR ALL USING (auth.uid() = user_id);

        CREATE TABLE vault_entries (
            id          BIGSERIAL PRIMARY KEY,
            user_id     UUID REFERENCES auth.users(id) ON DELETE CASCADE,
            svc         TEXT NOT NULL,
            usr         TEXT NOT NULL,
            epw         TEXT NOT NULL,
            memo        TEXT DEFAULT '',
            local_id    BIGINT,
            ts          TIMESTAMPTZ DEFAULT NOW()
        );
        ALTER TABLE vault_entries ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "own entries" ON vault_entries FOR ALL USING (auth.uid() = user_id);
    """

    def __init__(self):
        self.client = None
        self.user = None
        self._load_config()

    # ── 설정 ──────────────────────────────────────────────────────────────────

    def _load_config(self):
        if not _CONFIG_FILE.exists():
            return
        try:
            cfg = json.loads(_CONFIG_FILE.read_text())
            url = cfg.get("url", "").strip()
            key = cfg.get("key", "").strip()
            if url and key:
                from supabase import create_client
                self.client = create_client(url, key)
        except Exception:
            pass

    def is_configured(self) -> bool:
        return self.client is not None

    def configure(self, url: str, key: str):
        """Supabase URL + anon key를 저장하고 클라이언트를 초기화합니다."""
        from supabase import create_client
        client = create_client(url, key)
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        _CONFIG_FILE.write_text(json.dumps({"url": url, "key": key}))
        self.client = client

    # ── Auth ──────────────────────────────────────────────────────────────────

    def restore_session(self) -> bool:
        """저장된 토큰으로 세션을 복구합니다. 성공 시 True."""
        if not _SESSION_FILE.exists():
            return False
        try:
            data = json.loads(_SESSION_FILE.read_text())
            res = self.client.auth.set_session(
                data["access_token"], data["refresh_token"]
            )
            if res.user:
                self.user = res.user
                return True
        except Exception:
            pass
        return False

    def sign_in(self, email: str, password: str):
        """이메일/비밀번호로 Supabase Auth 로그인"""
        res = self.client.auth.sign_in_with_password(
            {"email": email, "password": password}
        )
        if res.user:
            self.user = res.user
            _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            _SESSION_FILE.write_text(json.dumps({
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token,
            }))
        return res

    def sign_up(self, email: str, password: str):
        """Supabase Auth 회원가입"""
        return self.client.auth.sign_up({"email": email, "password": password})

    def sign_out(self):
        """로그아웃 및 로컬 세션 삭제"""
        try:
            self.client.auth.sign_out()
        except Exception:
            pass
        self.user = None
        if _SESSION_FILE.exists():
            _SESSION_FILE.unlink()

    # ── vault_config ──────────────────────────────────────────────────────────

    def get_vault_config(self):
        """(salt: bytes, verify: bytes) 반환. 미설정 시 (None, None)."""
        uid = self.user.id
        res = (
            self.client.table("vault_config")
            .select("salt, verify")
            .eq("user_id", uid)
            .execute()
        )
        if not res.data:
            return None, None
        row = res.data[0]
        try:
            return base64.b64decode(row["salt"]), base64.b64decode(row["verify"])
        except Exception:
            return None, None

    def set_vault_config(self, salt: bytes, verify: bytes):
        """salt + verify token을 Supabase에 저장 (upsert)."""
        uid = self.user.id
        self.client.table("vault_config").upsert({
            "user_id": uid,
            "salt": base64.b64encode(salt).decode(),
            "verify": base64.b64encode(verify).decode(),
        }).execute()

    # ── vault_entries ─────────────────────────────────────────────────────────

    def add_password(self, svc_enc: bytes, usr_enc: bytes, pw_enc: bytes):
        """서비스·사용자·비밀번호 암호화 데이터를 Supabase에 저장합니다."""
        uid = self.user.id
        self.client.table("vault_entries").insert({
            "user_id": uid,
            "svc": base64.b64encode(svc_enc).decode(),
            "usr": base64.b64encode(usr_enc).decode(),
            "epw": base64.b64encode(pw_enc).decode(),
            "memo": "",
        }).execute()

    def get_all_passwords(self):
        """[(id, svc_enc, usr_enc, pw_enc)] 반환."""
        uid = self.user.id
        res = (
            self.client.table("vault_entries")
            .select("id, svc, usr, epw")
            .eq("user_id", uid)
            .execute()
        )
        return [
            (
                row["id"],
                base64.b64decode(row["svc"]),
                base64.b64decode(row["usr"]),
                base64.b64decode(row["epw"]),
            )
            for row in res.data
        ]

    def delete_password(self, entry_id: int):
        self.client.table("vault_entries").delete().eq("id", entry_id).execute()

    def clear_passwords(self):
        """현재 유저의 모든 항목 삭제"""
        uid = self.user.id
        self.client.table("vault_entries").delete().eq("user_id", uid).execute()
