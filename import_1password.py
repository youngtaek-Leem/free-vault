#!/usr/bin/env python3
"""
import_1password.py — 1Password 내보내기 → vault_migrate.json 변환

지원 형식:
  .1pif  — 1Password Interchange Format (구버전 1Password)
  .1pux  — 1Password 8 Unencrypted Export
  .csv   — 1Password CSV 내보내기

사용법:
  python3 import_1password.py export.1pif
  python3 import_1password.py export.1pux
  python3 import_1password.py export.csv

출력: vault_migrate.json
→ Connect Vault 앱 ⚙️ 설정 > 마이그레이션 가져오기 로 불러오세요.
"""
import json
import csv
import sys
import zipfile
import re
from pathlib import Path
from datetime import datetime


# ── 1PIF 파서 ─────────────────────────────────────────────────────────────────

def _pif_field(fields, *designations):
    """1PIF fields 배열에서 designation으로 값 찾기"""
    for d in designations:
        for f in fields:
            if f.get("designation") == d or f.get("name", "").lower() == d:
                v = f.get("value", "")
                if v:
                    return str(v)
    return ""


def parse_1pif(path):
    entries = []
    text = path.read_text(encoding="utf-8", errors="replace")

    # 각 항목은 ***uuid*** 구분자로 분리된 JSON 줄
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("***"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        if item.get("trashed") or item.get("inTrash"):
            continue

        type_name = item.get("typeName", "")
        title     = item.get("title", "제목 없음")
        location  = item.get("location", "")
        sc        = item.get("secureContents", {})
        fields    = sc.get("fields", [])
        notes     = sc.get("notesPlain", "")

        # URL: location 또는 secureContents.URLs
        url = location
        if not url:
            for u in sc.get("URLs", []):
                url = u.get("url", "") or u.get("u", "")
                if url:
                    break

        # ── 로그인 ────────────────────────────────────────────────────────────
        if type_name in ("webforms.WebForm", "wallet.computer.Login",
                         "wallet.computer.UnixServer", "wallet.computer.FTP"):
            username = (_pif_field(fields, "username", "email")
                        or sc.get("username", ""))
            password = (_pif_field(fields, "password")
                        or sc.get("password", ""))
            entries.append({
                "type": "login",
                "service": title,
                "username": username,
                "password": password,
                "memo": url or notes,
            })

        # ── 안심 노트 ─────────────────────────────────────────────────────────
        elif type_name == "securenotes.SecureNote":
            entries.append({
                "type": "note",
                "service": title,
                "username": "",
                "password": "",
                "memo": notes,
            })

        # ── 신용카드 ──────────────────────────────────────────────────────────
        elif type_name == "wallet.financial.CreditCard":
            card_num = sc.get("ccnum", "") or _pif_field(fields, "ccnum", "number")
            cvv      = sc.get("cvv", "")   or _pif_field(fields, "cvv", "verification_number")
            expiry   = sc.get("expiry", "") or _pif_field(fields, "expiry")
            holder   = sc.get("cardholder", "") or _pif_field(fields, "cardholder")
            entries.append({
                "type": "card",
                "service": title,
                "username": card_num.replace(" ", ""),
                "password": cvv,
                "memo": json.dumps({
                    "expiry": _parse_expiry(expiry) if expiry else "",
                    "holder": holder,
                    "memo": notes,
                }, ensure_ascii=False),
            })

        # ── 기타 (username/password 있으면 로그인으로 저장) ──────────────────
        else:
            username = (_pif_field(fields, "username", "email")
                        or sc.get("username", ""))
            password = (_pif_field(fields, "password")
                        or sc.get("password", ""))
            if username or password:
                entries.append({
                    "type": "login",
                    "service": title,
                    "username": username,
                    "password": password,
                    "memo": url or notes,
                })

    return entries


# ── 1PUX 파서 ─────────────────────────────────────────────────────────────────

def _field_val(fields, *keys):
    """loginFields / fields 배열에서 designation 또는 title로 값 찾기"""
    for key in keys:
        for f in fields:
            if f.get("designation") == key or f.get("title", "").lower() == key:
                v = f.get("value") or f.get("v") or ""
                if v:
                    return str(v)
    return ""


def _parse_expiry(raw):
    """1PUX expiry: 202612 → 12/26"""
    raw = str(raw).strip()
    if len(raw) == 6 and raw.isdigit():
        return raw[4:6] + "/" + raw[2:4]
    return raw


def parse_1pux(path):
    entries = []
    with zipfile.ZipFile(path) as z:
        with z.open("export.data") as f:
            data = json.load(f)

    for account in data.get("accounts", []):
        for vault in account.get("vaults", []):
            for item in vault.get("items", []):
                if item.get("trashed"):
                    continue

                cat = item.get("categoryUuid", "001")
                overview = item.get("overview", {})
                details = item.get("details", {})
                title = overview.get("title", "제목 없음")

                # URL (첫 번째)
                urls = overview.get("urls", [])
                url = urls[0].get("u", "") if urls else ""

                login_fields = details.get("loginFields", [])
                # sections 안의 fields도 합산
                section_fields = []
                for sec in details.get("sections", []):
                    section_fields.extend(sec.get("fields", []))

                # ── 로그인 (001) ──────────────────────────────────────────────
                if cat in ("001", "005"):
                    username = _field_val(login_fields, "username", "email")
                    password = _field_val(login_fields, "password")
                    if not username:
                        username = overview.get("ainfo", "") or overview.get("subtitle", "")
                    memo = url or details.get("notesPlain", "")
                    entries.append({
                        "type": "login",
                        "service": title,
                        "username": username,
                        "password": password,
                        "memo": memo,
                    })

                # ── 안심 노트 (003) ───────────────────────────────────────────
                elif cat == "003":
                    content = details.get("notesPlain", "")
                    entries.append({
                        "type": "note",
                        "service": title,
                        "username": "",
                        "password": "",
                        "memo": content,
                    })

                # ── 신용카드 (002) ────────────────────────────────────────────
                elif cat == "002":
                    card_num = _field_val(section_fields, "number", "ccnum")
                    cvv      = _field_val(section_fields, "verification_number", "cvv", "cvc")
                    expiry   = _field_val(section_fields, "expiry", "expdate")
                    holder   = _field_val(section_fields, "cardholder", "name")
                    note     = details.get("notesPlain", "")
                    entries.append({
                        "type": "card",
                        "service": title,
                        "username": card_num.replace(" ", ""),
                        "password": cvv,
                        "memo": json.dumps({
                            "expiry": _parse_expiry(expiry) if expiry else "",
                            "holder": holder,
                            "memo": note,
                        }, ensure_ascii=False),
                    })

                # ── 기타 항목은 로그인으로 최선 변환 ─────────────────────────
                else:
                    username = (_field_val(login_fields, "username", "email")
                                or overview.get("ainfo", "")
                                or overview.get("subtitle", ""))
                    password = _field_val(login_fields, "password")
                    memo     = url or details.get("notesPlain", "")
                    if username or password:
                        entries.append({
                            "type": "login",
                            "service": title,
                            "username": username,
                            "password": password,
                            "memo": memo,
                        })

    return entries


# ── CSV 파서 ──────────────────────────────────────────────────────────────────

def parse_csv(path):
    entries = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 1Password CSV 컬럼명 (버전마다 다름)
            def g(*keys):
                for k in keys:
                    v = row.get(k) or row.get(k.lower()) or row.get(k.title()) or ""
                    if v:
                        return v.strip()
                return ""

            title    = g("Title", "name")
            username = g("Username", "email")
            password = g("Password")
            url      = g("URL", "Url")
            notes    = g("Notes", "note")
            category = g("Type", "Category", "type").lower()

            if "note" in category:
                entries.append({
                    "type": "note",
                    "service": title,
                    "username": "",
                    "password": "",
                    "memo": notes,
                })
            else:
                entries.append({
                    "type": "login",
                    "service": title or url,
                    "username": username,
                    "password": password,
                    "memo": url or notes,
                })
    return entries


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"❌ 파일을 찾을 수 없습니다: {path}")
        sys.exit(1)

    ext = path.suffix.lower()
    if ext == ".1pif":
        entries = parse_1pif(path)
        src = "1pif"
    elif ext == ".1pux":
        entries = parse_1pux(path)
        src = "1pux"
    elif ext == ".csv":
        entries = parse_csv(path)
        src = "csv"
    else:
        print(f"❌ 지원하지 않는 형식: {ext}  (지원: .1pif, .1pux, .csv)")
        sys.exit(1)

    out = {
        "format": "connect-vault-migrate",
        "version": 1,
        "source": f"1password-{src}",
        "exported_at": datetime.now().isoformat(),
        "count": len(entries),
        "entries": entries,
    }

    out_path = path.parent / "vault_migrate.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    by_type = {}
    for e in entries:
        t = e.get("type", "login")
        by_type[t] = by_type.get(t, 0) + 1

    print(f"\n✅ {len(entries)}개 항목 변환 완료")
    for t, n in by_type.items():
        label = {"login": "로그인", "note": "안심 노트", "card": "신용카드"}.get(t, t)
        print(f"   {label}: {n}개")
    print(f"\n📁 저장: {out_path}")
    print()
    print("⚠️  이 파일에 복호화된 패스워드가 포함됩니다. 가져오기 후 즉시 삭제하세요!")
    print()
    print("👉 Connect Vault 열기 → ⚙️ 설정 → 마이그레이션 가져오기 → vault_migrate.json 선택")


if __name__ == "__main__":
    main()
