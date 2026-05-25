import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

_SENTINEL = "CONNECT_VAULT_OK"


class SecurityManager:
    """
    Zero-Knowledge 보안 관리자.
    PBKDF2로 키를 유도하고 AES-256-GCM으로 암호화합니다.
    마스터 패스워드 검증은 AES-GCM sentinel 방식을 사용합니다 (웹 앱과 동일).
    """

    def __init__(self):
        self.key = None

    def derive_key(self, master_password: str, salt: bytes):
        """마스터 패스워드와 솔트로 32바이트 암호화 키 유도 (PBKDF2-HMAC-SHA256)"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        self.key = kdf.derive(master_password.encode())
        return self.key

    def make_verify_token(self) -> bytes:
        """마스터 패스워드 검증용 AES-GCM 암호화 sentinel 생성"""
        return self.encrypt(_SENTINEL)

    def check_verify_token(self, token: bytes) -> bool:
        """저장된 sentinel 토큰으로 마스터 패스워드 검증"""
        try:
            return self.decrypt(token) == _SENTINEL
        except Exception:
            return False

    def encrypt(self, data: str) -> bytes:
        """AES-256-GCM 암호화 — [12-byte nonce | ciphertext]"""
        if not self.key:
            raise ValueError("먼저 마스터 패스워드로 키를 유도해야 합니다.")
        nonce = os.urandom(12)
        ct = AESGCM(self.key).encrypt(nonce, data.encode(), None)
        return nonce + ct

    def decrypt(self, encrypted_data: bytes) -> str:
        """AES-256-GCM 복호화"""
        if not self.key:
            raise ValueError("먼저 마스터 패스워드로 키를 유도해야 합니다.")
        nonce, ct = encrypted_data[:12], encrypted_data[12:]
        try:
            return AESGCM(self.key).decrypt(nonce, ct, None).decode()
        except Exception:
            raise ValueError("복호화 실패: 마스터 패스워드가 틀렸거나 데이터가 손상되었습니다.")

    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(16)
