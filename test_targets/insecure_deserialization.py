"""
보안 취약점 테스트: 역직렬화 및 데이터 처리

포함된 취약점:
- 안전하지 않은 역직렬화 (CWE-502)
- YAML 로드 취약점 (CWE-20)
- assert 문 사용 (CWE-703)
"""

import pickle
import yaml
import tempfile


def load_user_data(data: bytes):
    """취약: pickle 역직렬화 — 임의 코드 실행 가능"""
    # [취약] 신뢰할 수 없는 데이터를 pickle.loads로 역직렬화
    return pickle.loads(data)


def load_config(yaml_string: str) -> dict:
    """취약: yaml.load 사용 — 임의 코드 실행 가능"""
    # [취약] yaml.safe_load 대신 yaml.load 사용
    return yaml.load(yaml_string)


def validate_admin(user_role: str):
    """취약: assert로 보안 검증 — 최적화 시 무시됨"""
    # [취약] assert는 -O 옵션으로 실행 시 무시됨
    assert user_role == "admin", "Admin access required"
    return True


def save_temp_data(filename: str, data: str):
    """취약: 임시 파일 경쟁 조건"""
    # [취약] mktemp은 경쟁 조건에 취약
    path = tempfile.mktemp(suffix=filename)
    with open(path, "w") as f:
        f.write(data)
    return path
