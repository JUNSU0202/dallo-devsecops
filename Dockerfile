FROM python:3.11-slim

WORKDIR /app

# 시스템 패키지
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl && \
    rm -rf /var/lib/apt/lists/*

# Python 의존성
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 복사
COPY . .

# 대시보드 빌드 파일 (미리 빌드된 것 사용)
# dashboard/dist/ 가 있으면 서빙됨

# 포트
EXPOSE 8000

# 환경변수 기본값
ENV DATABASE_URL=postgresql://dallo:dallo_password@postgres:5432/dallo_db
ENV PYTHONUNBUFFERED=1

# 실행
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000"]
