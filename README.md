# Dallo DevSecOps

> LLM 에이전트 기반 소스코드 보안 취약점 분석 및 리팩토링 제안 시스템

**전북대학교 SW중심대학사업단 캡스톤디자인 | 팀 달로 | 기업연계: 올포랜드**

## 개요

코드를 업로드하면 보안 취약점을 자동으로 탐지하고, AI가 수정된 코드를 제안하는 DevSecOps 플랫폼입니다.

### 주요 기능

| # | 기능 | 설명 |
|---|------|------|
| 1 | **정적 분석** | Bandit(Python) + Semgrep(Java, JS, Go 등 30개+ 언어) |
| 2 | **AI 수정안 생성** | Gemini 메인 프로바이더 + Protocol 기반 확장 구조 (OpenAI, Anthropic, OpenRouter 대비) |
| 3 | **중복 제거 + 위험도 산정** | 동일 취약점 그룹화, CWE 기반 CVSS 스코어 매핑으로 critical/high/medium/low 분류 |
| 4 | **LLM 캐싱 + Batch 처리** | 동일 코드/취약점 재호출 방지 (Redis 캐시), 같은 파일 내 취약점 묶어서 한 번에 처리 |
| 5 | **민감정보 마스킹** | Microsoft Presidio 기반 탐지 (API 키, JWT, 주민번호 등) + 정규식 fallback |
| 6 | **API Key 인증** | X-API-Key 헤더 기반 인증, 타이밍 공격 방지 (hmac.compare_digest) |
| 7 | **비동기 작업 큐** | Celery + Redis 기반 분석 작업 관리 (메모리 fallback 지원) |
| 8 | **CI/CD 빌드 차단** | Critical/High 임계값 초과 시 GitHub Actions 빌드 실패 처리 |

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                    Web Dashboard (React)                  │
│  [코드 업로드] → [실시간 분석] → [결과 시각화/Diff 비교]    │
│  [API Key 로그인] → [분석 이력] → [리포트 생성/다운로드]    │
└────────────────────────┬────────────────────────────────┘
                         │ REST API (X-API-Key 인증)
┌────────────────────────▼────────────────────────────────┐
│              FastAPI Server + Celery Worker               │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  Bandit   │  │ Semgrep  │  │   LLM    │  │Validator│  │
│  │ (Python)  │  │(다중언어) │  │(Gemini)  │  │(문법/  │  │
│  │          │  │          │  │          │  │ 보안)  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘  │
│       └──────┬──────┘             │             │       │
│              ▼                    ▼             ▼       │
│  [중복 제거] → [위험도 산정] → [LLM 수정안] → [검증]    │
│              │                    │             │       │
│              └────────────┬──────┘─────────────┘       │
│                           ▼                             │
│               SQLite / PostgreSQL + Redis                │
└─────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│               GitHub Actions CI/CD                       │
│  PR → Bandit → 파이프라인 → 테스트 → CI Gate → PR 코멘트  │
└─────────────────────────────────────────────────────────┘
```

### 분석 파이프라인 (8단계)

```
1. 코드 입력 (대시보드 업로드 or GitHub PR)
       │
2. 정적 분석 (Bandit + Semgrep)
       │ → 취약점 탐지 (SQL Injection, XSS, Command Injection 등)
       │
3. 코드 문맥 추출
       │ → 취약점 포함 함수, import문, 주변 코드
       │
4. 중복 제거 (NEW)
       │ → 동일 rule_id + 유사 코드 패턴 그룹화, 대표 1건만 LLM에 전달
       │
5. 위험도 산정 (NEW)
       │ → CWE 기반 CVSS 스코어 매핑 → critical/high/medium/low 분류
       │
6. LLM 수정안 생성 (Gemini API)
       │ → 민감정보 마스킹 후 전송 → 수정 코드 + 근거 생성
       │ → 캐시 확인 (동일 코드/취약점이면 이전 결과 반환)
       │
7. 코드 검증
       │ → 문법 검사 (AST 파싱) + 보안 재검증 (수정 코드에 Bandit/Semgrep 재실행)
       │
8. 결과 제공
       ├→ 대시보드: 실시간 표시 + Diff 비교
       ├→ GitHub PR: 코멘트로 자동 게시
       └→ DB: 이력 저장 + 추이 분석
```

## 설치 및 실행

### 요구사항

- Python 3.11+
- Node.js 18+ (대시보드)
- Docker (Redis, PostgreSQL, SonarQube — 선택사항)

### 1. 의존성 설치

```bash
git clone https://github.com/JUNSU0202/dallo-devsecops.git
cd dallo-devsecops

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Presidio NLP 모델 설치 (선택)

```bash
python -m spacy download en_core_web_lg
```

> Presidio 미설치 시 정규식 기반 마스킹으로 자동 fallback됩니다.

### 3. 환경변수 설정

```bash
cp .env.example .env
```

#### 필수 환경변수

| 변수명 | 설명 | 생성 방법 |
|--------|------|-----------|
| `DALLO_ENCRYPTION_KEY` | DB 코드 스니펫 AES-256 암호화 키. **미설정 시 앱 시작 불가 (fail-fast)** | `python scripts/generate_encryption_key.py` |
| `GEMINI_API_KEY` | LLM 수정안 생성용 (쉼표 구분 다중 키 지원) | [Google AI Studio](https://aistudio.google.com/) |

#### 선택 환경변수

| 변수명 | 기본값 | 설명 |
|--------|--------|------|
| `DALLO_API_KEYS` | (없음 → 인증 스킵 + 경고) | API 인증 키 (콤마 구분 다중 키) |
| `LLM_PRIMARY_PROVIDER` | `gemini` | LLM 프로바이더 (`gemini`, `openrouter`) |
| `OPENROUTER_API_KEY` | — | OpenRouter 사용 시 필요 (Qwen 등) |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery 브로커 |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Celery 결과 백엔드 |
| `DATABASE_URL` | (빈 값 → SQLite) | PostgreSQL 연결 문자열 |
| `DALLO_KEY_PROVIDER` | `env` | 암호화 키 제공자 (`env`, 향후 `vault`) |
| `DALLO_GATE_CRITICAL_THRESHOLD` | `1` | CI Gate: critical 빌드 실패 임계값 |
| `DALLO_GATE_HIGH_THRESHOLD` | `5` | CI Gate: high 빌드 실패 임계값 |

### 4. 서버 실행

```bash
# 원클릭 실행
python start.py

# 또는 개별 실행
uvicorn api.server:app --reload --port 8000
```

### 5. 대시보드 (개발 모드)

```bash
cd dashboard
npm install
npm run dev
```

- **대시보드**: http://localhost:5173 (개발) / http://localhost:8000/dashboard (빌드)
- **API 문서**: http://localhost:8000/docs
- **로그인**: DALLO_API_KEYS에 설정한 키 입력

### 6. Celery Worker (선택 — Redis 필요)

```bash
# Redis 실행
docker run -d --name dallo-redis -p 6379:6379 redis:7-alpine

# Worker 실행 (별도 터미널)
celery -A api.celery_app worker --loglevel=info
```

### Graceful Degradation

외부 의존성이 없어도 핵심 기능이 동작하도록 설계되었습니다:

| 의존성 | 미설치/미실행 시 | 동작 |
|--------|----------------|------|
| **Redis** | 미실행 | 메모리 기반 작업 관리 + 메모리 캐시로 자동 fallback |
| **Presidio** | 미설치 | 정규식 기반 민감정보 마스킹으로 fallback |
| **DALLO_API_KEYS** | 미설정 | 인증 스킵 + 경고 로그 (개발 환경용) |
| **PostgreSQL** | 미실행 | SQLite 자동 사용 |

## Security Notice

> **암호화 키 관리**: DB 코드 스니펫은 AES-256으로 암호화됩니다.
> 암호화 키는 반드시 환경변수(`DALLO_ENCRYPTION_KEY`)로 설정해야 하며,
> 소스 코드에 하드코딩하면 안 됩니다.
>
> ```bash
> python scripts/generate_encryption_key.py
> # 출력된 키를 .env 파일에 설정
> ```
>
> **경고**: 이전 커밋 히스토리에 개발용 기본 키(`dallo-devsecops-default-key-*`)가
> 포함되어 있습니다. 운영 환경에서는 반드시 새 키를 생성하여 사용하고,
> 기존 데이터는 새 키로 재암호화(키 로테이션)하세요.

## 테스트

```bash
# 전체 테스트 실행 (96개)
DALLO_ENCRYPTION_KEY=test-key python -m pytest tests/ -v

# 특정 모듈만
python -m pytest tests/test_encryption.py -v
python -m pytest tests/test_auth.py -v
python -m pytest tests/test_pipeline_integration.py -v
```

| 테스트 파일 | 검증 대상 | 개수 |
|-------------|-----------|------|
| `test_bandit_runner.py` | Bandit 분석기, progress bar 파싱 | 10 |
| `test_context_extractor.py` | 코드 문맥 추출 | 5 |
| `test_llm_parser.py` | LLM 응답 파싱 | 8 |
| `test_syntax_checker.py` | 문법 검사 | 6 |
| `test_api_server.py` | API 엔드포인트 + 인증 | 8 |
| `test_encryption.py` | 암호화 fail-fast, 암복호화, KeyProvider | 10 |
| `test_auth.py` | API Key 인증, 타이밍 공격 방지 | 6 |
| `test_dedup_risk.py` | 중복 제거, 위험도 산정, CWE 매핑 | 10 |
| `test_cache_batch.py` | LLM 캐시, 배치 처리, JSON 파서 | 10 |
| `test_sensitive_masker.py` | AWS/JWT/GitHub/Slack/주민번호 마스킹 | 12 |
| `test_ci_gate.py` | CI Gate PASS/FAIL, threshold | 7 |
| `test_pipeline_integration.py` | 파이프라인 통합 순서 검증 | 4 |

## 프로젝트 구조

```
dallo-devsecops/
│
├── analyzer/                        # 정적 분석 모듈
│   ├── bandit_runner.py             # Bandit 분석기 (Python)
│   ├── semgrep_runner.py            # Semgrep 분석기 (다중 언어)
│   ├── sonar_runner.py              # SonarQube 연동
│   ├── context_extractor.py         # 취약점 주변 코드 문맥 추출
│   ├── result_parser.py             # 분석 결과 파싱/병합
│   ├── dependency_scanner.py        # 의존성 취약점 스캔
│   ├── pipeline.py                  # 통합 분석 파이프라인 (8단계)
│   ├── deduplicator.py              # 중복 취약점 그룹화
│   └── risk_scorer.py               # CWE 기반 위험도 산정
│
├── agent/                           # LLM 에이전트
│   ├── llm_agent.py                 # DalloAgent (Facade — 프롬프트/파싱/재시도)
│   ├── cache.py                     # LLM 응답 캐싱 (Redis/메모리)
│   ├── batch_processor.py           # 파일별 배치 처리
│   ├── response_parser.py           # JSON 응답 파서
│   ├── provider_factory.py          # LLM 프로바이더 Factory
│   ├── providers/                   # LLM 프로바이더 (Protocol 기반)
│   │   ├── base.py                  # LLMProvider Protocol 정의
│   │   ├── gemini_provider.py       # Gemini (메인, 키 로테이션)
│   │   ├── openrouter_provider.py   # OpenRouter (Qwen 등)
│   │   ├── openai_provider.py       # OpenAI (비활성 보존)
│   │   └── anthropic_provider.py    # Anthropic (비활성 보존)
│   └── prompts/                     # 프롬프트 템플릿
│       └── gemini_refactor_prompt.py
│
├── validator/                       # 코드 검증
│   ├── syntax_checker.py            # 문법 검사 (AST 파싱)
│   ├── security_checker.py          # 보안 재검증 (수정 코드 재스캔)
│   └── test_runner.py               # 샌드박스 테스트 실행
│
├── api/                             # REST API 서버
│   ├── server.py                    # FastAPI (분석/조회/대시보드)
│   ├── auth.py                      # X-API-Key 인증 미들웨어
│   ├── celery_app.py                # Celery 인스턴스 (Redis 브로커)
│   └── tasks.py                     # Celery 분석 태스크
│
├── dashboard/                       # 웹 대시보드 (React + Vite)
│   └── src/
│       ├── api/client.js            # API fetch 래퍼 (X-API-Key 자동 포함)
│       └── components/
│           ├── LoginView.jsx        # API Key 로그인 화면
│           ├── AnalyzeView.jsx      # 코드 업로드 + 실시간 분석
│           ├── StatsCards.jsx       # 통계 카드
│           ├── VulnTable.jsx        # 취약점 목록 테이블
│           ├── PatchView.jsx        # AI 수정안 + Diff 비교
│           ├── FileChart.jsx        # 파일별 취약점 차트
│           ├── TypeChart.jsx        # 유형별 파이 차트
│           ├── DependencyView.jsx   # 의존성 취약점 검사
│           ├── ReportView.jsx       # 리포트 생성/미리보기
│           └── HistoryView.jsx      # 분석 이력 + 추이 차트
│
├── db/                              # 데이터베이스
│   ├── models.py                    # SQLAlchemy ORM
│   ├── service.py                   # DB 저장/조회 서비스
│   └── key_provider.py              # 암호화 키 제공자 (env/vault 추상화)
│
├── shared/                          # 공통 모듈
│   ├── schemas.py                   # VulnerabilityReport, PatchSuggestion, AnalysisSession
│   ├── encryption.py                # AES-256 암호화 (환경변수 기반, fail-fast)
│   ├── masking.py                   # 민감정보 마스킹 (Presidio + 정규식 fallback)
│   └── cwe_severity.json            # CWE → CVSS 스코어 매핑 테이블
│
├── scripts/                         # 실행/유틸리티 스크립트
│   ├── run_analysis.py              # CLI 전체 파이프라인
│   ├── post_pr_comment.py           # GitHub Actions PR 코멘트 게시
│   ├── generate_encryption_key.py   # AES-256 암호화 키 생성
│   └── ci_gate.py                   # CI/CD 보안 게이트 (threshold 기반)
│
├── config/                          # 설정 파일
│   ├── config.yaml                  # 파이프라인 설정 (중복 제거, 위험도, 정책 필터)
│   ├── bandit.yml                   # Bandit 분석 설정
│   └── sonar-project.properties     # SonarQube 설정
│
├── tests/                           # 유닛 테스트 (96개)
├── test_targets/                    # 취약점 시연용 샘플 코드 (의도적 취약점 포함)
├── integrations/                    # GitHub 연동 (PR 코멘트)
├── docker/                          # Docker Compose (Redis, PostgreSQL, SonarQube)
│
├── .github/
│   ├── workflows/security-analysis.yml  # CI/CD 워크플로우
│   └── dallo-gate.yml               # CI Gate 임계값 설정
├── .env.example                     # 환경변수 템플릿
├── start.py                         # 원클릭 실행 스크립트
└── requirements.txt
```

> **참고**: `test_targets/` 디렉토리는 시스템 검증용 의도적 취약 샘플 코드입니다.
> Bandit 프로덕션 스캔 대상에서 제외됩니다.

## Tech Stack

| 구분 | 기술 |
|------|------|
| **정적 분석** | Bandit 1.7+, Semgrep 1.50+, SonarQube 10 |
| **AI/LLM** | Google Gemini 2.0 Flash Lite (메인), OpenRouter/Qwen (대체) |
| **민감정보 탐지** | Microsoft Presidio + 정규식 fallback |
| **백엔드** | Python 3.11+, FastAPI, Celery, SQLAlchemy |
| **비동기 큐** | Celery + Redis |
| **프론트엔드** | React 19, Recharts, Vite 6 |
| **데이터베이스** | SQLite (개발) / PostgreSQL 16 (운영) |
| **암호화** | AES-256 (Fernet), 환경변수 기반 키 관리 |
| **CI/CD** | GitHub Actions + CI Gate (threshold 기반 빌드 차단) |
| **컨테이너** | Docker, Docker Compose |

## API Endpoints

모든 데이터 엔드포인트는 `X-API-Key` 헤더 인증이 필요합니다.

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/` | API 정보 (인증 불필요) |
| GET | `/api/stats` | 대시보드 통계 |
| GET | `/api/vulnerabilities` | 취약점 목록 (필터: severity, tool, file_path) |
| GET | `/api/vulnerabilities/by-file` | 파일별 취약점 집계 |
| GET | `/api/vulnerabilities/by-type` | 유형별 취약점 집계 |
| GET | `/api/patches` | AI 수정 제안 목록 |
| GET | `/api/sessions` | 분석 세션 이력 |
| GET | `/api/sessions/{session_id}` | 세션 상세 조회 |
| POST | `/api/analyze` | 코드 분석 실행 (비동기) |
| GET | `/api/analyze/{job_id}` | 분석 진행 상태 조회 |
| GET | `/api/analyze/status/{task_id}` | Celery 태스크 상태 (Redis 사용 시) |
| POST | `/api/quick-scan` | 정규식 기반 빠른 스캔 (밀리초 응답) |
| POST | `/api/quick-scan-project` | 프로젝트 전체 빠른 스캔 |
| POST | `/api/analyze/file` | 파일 업로드 분석 |
| POST | `/api/apply-patch` | 수정안 적용 (GitHub PR 자동 생성) |
| GET | `/api/dependencies` | 의존성 취약점 스캔 |
| POST | `/api/dependencies/scan` | 의존성 취약점 스캔 (텍스트 입력) |
| GET | `/api/report/generate` | 분석 리포트 생성 (HTML/Markdown) |
| GET | `/api/report/download/{filename}` | 리포트 다운로드 |
| GET | `/api/report/preview` | 리포트 미리보기 |
| GET | `/dashboard` | 웹 대시보드 (인증 불필요) |

## CI/CD 정책

### GitHub Actions 워크플로우

PR 발생 시 자동 실행 (`.py` 파일 변경 감지):

1. **Bandit 정적 분석** — 취약점 발견 시에도 리포트 정상 생성 (exit code 분기 처리)
2. **전체 분석 파이프라인** — Bandit → 중복 제거 → 위험도 산정 → LLM (키 있을 때만)
3. **테스트 실행** — 96개 유닛 테스트
4. **보안 게이트** — Critical 1개 이상 또는 High 5개 이상 시 빌드 실패
5. **PR 코멘트** — 분석 결과 자동 게시

### 보안 게이트 임계값

`.github/dallo-gate.yml`에서 프로젝트별 조정 가능:

```yaml
critical_threshold: 1   # critical N개 이상 → 빌드 실패
high_threshold: 5        # high N개 이상 → 빌드 실패
```

환경변수 `DALLO_GATE_CRITICAL_THRESHOLD`, `DALLO_GATE_HIGH_THRESHOLD`로도 오버라이드 가능.

## Team

| 이름 | 역할 | 담당 |
|------|------|------|
| 박영주 | 팀장 / AI | LLM 코드 분석 및 리팩토링 모듈 |
| 이준수 | 백엔드 / DevSecOps | 정적 분석, CI/CD, API, 대시보드, DB |
| 임해안 | 프론트엔드 / 데이터 | 웹 대시보드 UI, DB 설계, 시각화 |

**지도교수**: 김윤경 (SW중심대학사업단)
**참여기업**: 올포랜드 (담당: 김민솔)
