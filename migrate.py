#!/usr/bin/env python3
"""
migrate.py — 구 SQLite vault.db → vault_migrate.json 변환 스크립트
vault.html의 "마이그레이션 가져오기"로 불러오세요.

⚠️  이 스크립트는 구 SQLite/iCloud 데이터를 웹 앱으로 이전할 때 한 번만 사용합니다.
    새 Supabase 백엔드로 전환한 이후에는 웹 앱 설정의 "내보내기/가져오기"를 사용하세요.
"""
import sqlite3
import json
import sys
from pathlib import Path
from getpass import getpass


def find_db():
    icloud = (
        Path.home()
        / "Library/Mobile Documents/com~apple~CloudDocs/ConnectVault/vault.db"
    )
    local = Path(__file__).parent / "vault.db"
    if icloud.exists():
        return str(icloud)
    if local.exists():
        return str(local)
    return None


def main():
    db_path = find_db()
    if not db_path:
        print("❌ vault.db 를 찾을 수 없습니다.")
        sys.exit(1)
    print(f"✅ DB 발견: {db_path}")

    try:
        from security import SecurityManager
    except ImportError:
        print("❌ security.py 가 같은 폴더에 있어야 합니다.")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    row_salt = conn.execute(
        "SELECT value FROM config WHERE key='master_salt'"
    ).fetchone()
    row_hash = conn.execute(
        "SELECT value FROM config WHERE key='master_hash'"
    ).fetchone()

    if not row_salt:
        print("❌ master_salt 설정 정보가 없습니다.")
        sys.exit(1)

    salt = row_salt[0]
    password = getpass("마스터 패스워드 입력: ")

    # Argon2 검증 (설치된 경우에만)
    if row_hash:
        stored = row_hash[0]
        stored = stored.decode() if isinstance(stored, bytes) else stored
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            if not ph.verify(stored, password):
                print("❌ 마스터 패스워드가 틀렸습니다.")
                sys.exit(1)
            print("✅ Argon2 검증 성공")
        except ImportError:
            print("⚠️  argon2-cffi 미설치 — 비밀번호 사전 검증 건너뜀 (복호화로 확인)")
    else:
        print("⚠️  master_hash 없음 — 복호화로 검증")

    sec = SecurityManager()
    sec.derive_key(password, salt)

    rows = conn.execute(
        "SELECT id, service, username, encrypted_password, created_at FROM vault"
    ).fetchall()

    entries = []
    for eid, svc, usr, epw, ts in rows:
        try:
            plain = sec.decrypt(epw)
        except Exception as e:
            print(f"⚠️  id={eid} ({svc}) 복호화 실패: {e}")
            plain = "DECRYPT_ERROR"
        entries.append({
            "service": svc,
            "username": usr or "",
            "password": plain,
            "created_at": ts or "",
        })

    out = {
        "format": "connect-vault-migrate",
        "version": 1,
        "exported_at": __import__("datetime").datetime.now().isoformat(),
        "count": len(entries),
        "entries": entries,
    }

    out_path = Path(__file__).parent / "vault_migrate.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"\n✅ {len(entries)}개 항목 변환 완료 → {out_path}")
    print("⚠️  이 파일에는 복호화된 패스워드가 포함됩니다. 가져오기 후 즉시 삭제하세요!")
    print("\nvault.html 열기 → 설정 → 마이그레이션 가져오기 → vault_migrate.json 선택")


if __name__ == "__main__":
    main()
