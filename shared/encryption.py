"""
AES-256 암호화 모듈 (shared/encryption.py)

DB에 저장되는 코드 스니펫을 AES-256으로 암호화/복호화합니다.

사용법:
    from shared.encryption import CodeEncryptor

    encryptor = CodeEncryptor()  # 키는 환경변수 ENCRYPTION_KEY에서 로드
    encrypted = encryptor.encrypt("sensitive code here")
    decrypted = encryptor.decrypt(encrypted)
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet


def _derive_key(secret: str) -> bytes:
    """문자열 시크릿에서 Fernet 호환 키(32바이트 base64)를 유도합니다."""
    key_bytes = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


class CodeEncryptor:
    """AES-256 기반 코드 스니펫 암호화/복호화"""

    def __init__(self, key: str = None):
        """
        Args:
            key: 암호화 키 (없으면 ENCRYPTION_KEY 환경변수 사용,
                 그것도 없으면 기본 키 생성)
        """
        secret = key or os.environ.get("ENCRYPTION_KEY", "")
        if not secret:
            # 기본 키 (개발용 — 운영에서는 반드시 환경변수 설정)
            secret = "dallo-devsecops-default-key-change-in-production"

        self._fernet = Fernet(_derive_key(secret))

    def encrypt(self, plaintext: str) -> str:
        """
        문자열을 AES-256으로 암호화합니다.

        Args:
            plaintext: 평문

        Returns:
            base64 인코딩된 암호문
        """
        if not plaintext:
            return ""
        encrypted = self._fernet.encrypt(plaintext.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """
        암호문을 복호화합니다.

        Args:
            ciphertext: encrypt()로 생성된 암호문

        Returns:
            원본 평문
        """
        if not ciphertext:
            return ""
        decrypted = self._fernet.decrypt(ciphertext.encode("utf-8"))
        return decrypted.decode("utf-8")

    def is_encrypted(self, text: str) -> bool:
        """텍스트가 암호화된 상태인지 확인합니다."""
        try:
            self._fernet.decrypt(text.encode("utf-8"))
            return True
        except Exception:
            return False
