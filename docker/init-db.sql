-- Dallo DevSecOps DB 초기화
-- dallo_db: 분석 결과 저장 (기본 DB로 자동 생성됨)
-- sonarqube: SonarQube 전용 DB

CREATE DATABASE sonarqube;
GRANT ALL PRIVILEGES ON DATABASE sonarqube TO dallo;
