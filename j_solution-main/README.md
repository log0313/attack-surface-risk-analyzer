# 🛡️ 외부 통합 위험도 평가 시스템 (Attack Surface Risk Analyzer)

> 외부 노출 자산을 자동으로 탐색하고, CVE 취약점을 매칭하여 위험도를 분석·시각화하는 통합 보안 대시보드 PoC

---

## 📋 목차

- [프로젝트 개요](#-프로젝트-개요)
- [주요 기능](#-주요-기능)
- [기술 스택](#-기술-스택)
- [시스템 아키텍처](#-시스템-아키텍처)
- [화면 구성](#-화면-구성)
- [사전 요구사항](#-사전-요구사항)
- [설치 및 실행](#-설치-및-실행)
- [CVE 데이터 초기 로드](#-cve-데이터-초기-로드-최초-1회)
- [환경 변수 설정](#-환경-변수-설정)
- [제약 사항](#-제약-사항)
- [팀 구성](#-팀-구성)

---

## 🔍 프로젝트 개요

DX·AX 가속화로 클라우드 및 제3자 연계 서비스가 급증하면서 IT 인프라의 공격 표면(Attack Surface)이 방대해졌습니다.  
본 프로젝트는 **외부 노출 자산의 위험도를 자동으로 수집·분석·시각화하는 통합 보안 진단 PoC**입니다.

| 항목 | 내용 |
|------|------|
| **프로젝트 유형** | PoC (Proof of Concept) |
| **대상 사용자** | 기업 보안 담당자 및 IT 인프라 관리자 |
| **수행 기간** | 2026년 3월 1일 ~ 7월 31일 (총 4개월) |
| **참여 인원** | 8명 (기업체 멘토 1, 지도교수 1, 대학원생 2, 학부생 4) |

---

## ✨ 주요 기능

### 🔎 Asset Discovery
- 도메인 입력 → Subfinder → Naabu → Nmap → HTTPX 자동 스캔 파이프라인
- 실시간 스캔 진행 상태 표시 (단계별 진행 표시)
- 스캔 완료 후 자산 목록 자동 업데이트
- 자산 검색 및 위험도 필터링 (Critical / High / Medium / Low)
- 데이터 초기화 기능

### ⚠️ Risk Analysis
- 스캔된 자산별 CVE 매칭 결과 목록
- CVSS · EPSS · KEV 기반 통합 위험도 산정
- 자산명 / CVE ID / 서비스명 검색
- 자산별 필터 드롭다운
- 위험도 상세 분석 페이지 (종합 리스크 스코어 게이지, 관련 CVE 목록)

### 🤖 AI Reports
- Gemini 2.5 Flash 기반 보안 보고서 자동 생성
- 위험 요약, 원인 분석, 대응 권고사항 포함
- 취약점 상세 페이지에서 원클릭 보고서 생성
- 생성된 보고서 편집 및 클립보드 복사

### 📊 Overview
- 전체 공격 표면 현황 요약 (자산 수, 활성 포트, 위험도 점수, Critical 건수)
- 위험도 분포 파이차트 (실시간 스캔 데이터 반영)
- 취약점 증감 추이 라인차트
- 위험 자산 Top 5

---

## 🛠 기술 스택

### Frontend / Backend
| 기술 | 용도 |
|------|------|
| Next.js 16 (App Router) | 풀스택 웹 프레임워크 |
| TypeScript | 타입 안전성 |
| Recharts | 위험도 분포 / 추이 차트 |
| ioredis | Redis 큐 연동 |
| @opensearch-project/opensearch | OpenSearch 클라이언트 |

### 백엔드 (Python)
| 기술 | 용도 |
|------|------|
| Python Worker | Redis 큐 소비, 스캔 파이프라인 제어 |
| FastAPI + Uvicorn | LLM Report API 서버 |
| google-generativeai | Gemini AI 보고서 생성 |
| opensearch-py | CVE DB 조회 및 결과 저장 |

### 인프라
| 서비스 | 용도 |
|--------|------|
| OpenSearch (Docker) | CVE DB (296,000+건), 스캔 결과 저장 |
| Redis (Docker) | 스캔 작업 큐 (LPUSH/BLPOP) |

### 스캐너 도구
| 도구 | 용도 |
|------|------|
| Subfinder | 서브도메인 열거 |
| Naabu | 포트 스캔 |
| Nmap | 서비스 및 버전 탐지 |
| HTTPX | 웹 기술 스택 분석 |

### 외부 데이터
| 소스 | 용도 |
|------|------|
| NVD API v2 | CVE 데이터 수집 (296,000+건) |
| EPSS | 취약점 악용 가능성 점수 |
| CISA KEV | 실제 악용 중인 취약점 목록 |
| Gemini API | AI 보안 보고서 생성 |

---

## 🏗 시스템 아키텍처

```
Browser
  └── Next.js Dashboard (Port 3000)
        ├── LPUSH ──► Redis Queue (Port 6400)
        │                 └── BLPOP ──► Python Worker
        │                                   └── Scanner Engine
        │                                         ├── Subfinder  (서브도메인 열거)
        │                                         ├── Naabu      (포트 스캔)
        │                                         ├── Nmap       (서비스 탐지)
        │                                         └── HTTPX      (기술 스택 분석)
        │
        ├── Query ──► OpenSearch (Port 9200)
        │               ├── scan_assets      (스캔된 자산)
        │               ├── scan_results     (CVE 매칭 결과)
        │               └── vulnerability_cve (CVE DB)
        │
        └── POST ──► LLM Report API (Port 8001)
                        └── Gemini 2.5 Flash
```

---

## 🖥 화면 구성

> 기본 테마: 다크 모드 — 보안 실무자의 장시간 작업 피로도 최소화

| 화면 | 주요 내용 |
|------|-----------|
| **Overview** | 전체 위험도 점수, Critical 건수, 위험 자산 Top 5, 위험도 분포/추이 차트 |
| **Asset Discovery** | 도메인 스캔 제어, 자산 목록, 위험도 필터, 초기화 |
| **Risk Analysis** | CVE 목록, 자산 검색/필터, 위험도 상세 (게이지, CVE 목록) |
| **AI Reports** | Gemini 기반 보안 보고서 자동 생성, 대응 가이드 |

---

## 📦 사전 요구사항

- Node.js 18+
- Python 3.11+
- Docker Desktop
- 스캐닝 도구 (PATH 등록 필요): `subfinder`, `naabu`, `nmap`, `httpx`

---

## 🚀 설치 및 실행

### 1. 저장소 클론

```bash
git clone https://github.com/{username}/{repo}.git
cd {repo}
```

### 2. Next.js 의존성 설치

```bash
npm install
```

### 3. Python 의존성 설치

```bash
# Python Worker
pip install redis opensearch-py urllib3

# LLM Report Module
pip install fastapi uvicorn python-dotenv pydantic opensearch-py google-generativeai
```

### 4. 환경변수 설정

프로젝트 루트에 `.env.local` 파일 생성 → [환경 변수 설정](#-환경-변수-설정) 참고

---

## ▶️ 실행 순서

### Step 1 — Docker 컨테이너 시작

```bash
docker start opensearch-node redis-queue
```

### Step 2 — OpenSearch 상태 확인 (30초~1분 대기)

```bash
docker exec opensearch-node curl -s -k -u "admin:비밀번호" \
  "https://localhost:9200/_cat/health?v"
# status: yellow 또는 green 이면 정상
```

### Step 3 — Python Worker 실행 (새 터미널)

```bash
python worker.py
# [Worker] 작업 대기 중... 출력 확인
```

### Step 4 — LLM Report API 실행 (새 터미널)

```bash
cd "LLM Report Module"
python api_server.py
# Uvicorn running on http://0.0.0.0:8001 확인
```

### Step 5 — Next.js 개발 서버 실행 (새 터미널)

```bash
npm run dev
# http://localhost:3000 접속
```

---

## 🔄 종료 방법

- **Next.js, Worker, LLM API** — 각 터미널 창 닫기
- **Docker 컨테이너**:

```bash
docker stop opensearch-node redis-queue
```

---

## 📥 CVE 데이터 초기 로드 (최초 1회)

NVD에서 전체 CVE 데이터를 다운로드하고 OpenSearch에 색인합니다. (~30분 소요)

```bash
cd "External Asset Discovery Module"

# 1. NVD 전체 데이터 다운로드
python nvd_manager.py

# 2. OpenSearch에 색인
python nvd_to_opensearch.py
```

---

## ⚙️ 환경 변수 설정

### Next.js — `.env.local`

```env
REDIS_URL=redis://localhost:6400
OPENSEARCH_URL=https://localhost:9200
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD="your_opensearch_password"
GEMINI_API_KEY=your_gemini_api_key
LLM_REPORT_URL=http://localhost:8001
SCAN_QUEUE_NAME=scan_jobs
```

### LLM Report Module — `LLM Report Module/.env`

```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=your_opensearch_password
REPORT_LANGUAGE=ko
API_HOST=0.0.0.0
API_PORT=8001
```

---

## 🌐 스캔 허용 테스트 대상

| 도메인 | 비고 |
|--------|------|
| `scanme.nmap.org` | Nmap 공식 테스트 서버 |
| `nmap.org` | 서브도메인 다수, 다양한 서비스 |
| `vulnweb.com` | Acunetix 공식 취약 서버 |

> ⚠️ **주의**: 허가되지 않은 외부 도메인 스캔은 법적 문제가 될 수 있습니다.  
> 반드시 스캔 허용이 명시된 대상에만 사용하세요.

---

## ⚠️ 제약 사항

- **PoC 수준**: 상용화 완제품이 아닌 개념 증명 단계의 시스템입니다.
- **외부 API 의존성**: NVD, EPSS, Gemini API의 Rate Limit 및 서비스 상태에 영향을 받습니다.
- **테스트 환경**: 실제 운영망 테스트는 사전 협의된 인가 범위 내에서만 수행됩니다.
- **OpenSearch 단일 노드**: 단일 노드 구성으로 클러스터 상태가 yellow로 표시되나 정상 동작합니다.

---

## 💡 기대 효과

- **보안 수준 향상**: 주기적인 통합 평가 체계로 외부 노출 자산 보안 수준 강화
- **우선순위 효율화**: CVSS·EPSS·KEV 종합 정량적 모델로 의사결정 속도 향상
- **자동화**: 수동 점검 대비 탐색·분석·보고서 작성 과정 자동화

---

## 👥 팀 구성

| 역할 | 인원 |
|------|------|
| 기업체 멘토 | 1명 |
| 지도교수 | 1명 |
| 대학원생 | 2명 |
| 학부생 | 4명 |
