# EPSS-KEV 갭 기반 금융권 선제 대응 모델
**EPSS-KEV Gap Based Early Warning Model**

---

## 모델 이름

**EPSS-KEV Gap Based Early Warning Model**
EPSS-KEV 갭 기반 금융권 선제 대응 모델

---

## 모델 목적

금융권 인프라에서 **KEV 등재 전에 먼저 위험 신호를 포착**하여, 실제 공격 피해가 발생하기 전에 선제적으로 대응하는 것을 목적으로 합니다.

기존 모델들이 "이미 악용된 취약점(KEV=True)"에 높은 점수를 부여하는 방식에서 벗어나, **EPSS 백분위가 높지만 아직 KEV에 등재되지 않은 취약점**에 주목합니다. 이 갭(Gap) 구간이 바로 선제 대응의 골든 타임입니다.

---

## 기존 CVSS/EPSS/KEV 단순 가중치 모델과의 차이점

| 항목 | 기존 모델 | 본 모델 |
|------|-----------|---------|
| KEV=True 처리 | 가산점 부여 (이미 악용됨) | 가산점 부여하되, 핵심이 아님 |
| EPSS 높음 + KEV=False | 특별 처리 없음 | **KEV Gap Bonus 추가 부여** |
| 금융 자산 특화 | 일반적 자산 중요도 | 금융 핵심 시스템 키워드 특화 |
| 초점 | 과거/현재 위협 식별 | **미래 위협 선제 식별** |
| 분류 체계 | 점수 범위 기반 | **Immediate Watchlist 별도 카테고리** |

---

## 왜 EPSS가 높지만 KEV에 없는 취약점을 선제적으로 봐야 하는가

EPSS(Exploit Prediction Scoring System)는 다음 요소들을 학습하여 **향후 30일 내 실제 공격에 사용될 확률**을 예측합니다:

- GitHub, Exploit-DB 등의 PoC/Exploit 코드 게시
- 취약점 스캐너에서의 탐지 활동
- 보안 커뮤니티 및 소셜 미디어 논의
- 다크웹 및 해킹 포럼에서의 언급

즉, EPSS 백분위가 높다는 것은 **해당 취약점이 실제 악용될 가능성이 상대적으로 높다는 신호로 볼 수 있습니다.**

반면 KEV(Known Exploited Vulnerabilities)는 CISA가 **실제 공격이 발생했음을 확인**한 이후에 등재됩니다. 따라서:

> EPSS 급상승 → (시간 간격 발생) → 실제 공격 발생 → CISA 확인 → KEV 등재

금융기관이 KEV 등재를 기다려서 대응한다면, 이미 공격이 시작된 이후입니다.

---

## EPSS와 KEV의 시간차 문제

KEV 등재는 실제 악용 증거 확인 이후 이루어지므로, 상황에 따라 수일 이상의 지연이 발생할 수 있습니다.

```
PoC 공개 → EPSS 상승 → 공격자 무기화 → 실제 공격 → CISA 확인 → KEV 등재
   ↑                                                              ↑
 선제 대응 가능 시점                                         기존 모델 반응 시점
```

특히 **금융 인프라(VPN, MFT, API Gateway, IAM 등)**는 초기 침투 경로로 자주 활용되기 때문에, 이 시간차 구간에서의 대응이 매우 중요합니다.

---

## 점수 계산식

### Final Score (최대 100점)

```
Final Score = min(100,
    Base Exploitability Score
    + KEV Gap Bonus
    + Financial Impact Score
)
```

### Base Exploitability Score (최대 75점)

```
Base Exploitability Score =
    CVSS_norm × 25          # CVSS 점수 정규화 (cvss_score / 10)
    + EPSS_percentile × 35  # EPSS 백분위 반영 (가장 큰 비중)
    + KEV_flag × 15         # KEV 등재 여부 (in_kev=True이면 1)
```

> EPSS_percentile에 35점을 배정하여 예측 기반 위협 탐지를 강조합니다.

### KEV Gap Bonus (최대 20점)

```
if EPSS_percentile >= 0.95 and KEV=False → +20
if EPSS_percentile >= 0.90 and KEV=False → +15
if EPSS_percentile >= 0.80 and KEV=False → +10
else                                      → +0
```

> KEV에 아직 없지만 공격 가능성이 높은 취약점에 추가 점수를 부여합니다.

### Financial Impact Score (최대 30점)

```
Financial Impact Score =
    Critical_Asset_flag × 10  # 금융 핵심 자산 여부
    + Auth_or_RCE_flag × 8    # 인증 우회 또는 원격 코드 실행 여부
    + Internet_Exposed_flag × 7  # 인터넷 노출 여부
    + Ransomware_flag × 5     # 랜섬웨어 캠페인 악용 이력 여부 (소폭 가산)
```

---

## KEV Gap Bonus 설명

KEV Gap Bonus는 이 모델의 핵심 차별화 요소입니다.

- KEV=True인 취약점은 이미 공격이 발생한 **사후 대응** 대상입니다.
- EPSS가 높고 KEV=False인 취약점은 **선제 대응**이 가능한 골든 타임 상태입니다.
- 금융권에서 이 갭 구간의 취약점을 먼저 처리하면, KEV 등재 전에 공격 표면을 줄일 수 있습니다.

---

## Priority Category 설명

| 카테고리 | 조건 | 의미 |
|----------|------|------|
| **Immediate Watchlist** | KEV=False, EPSS_percentile ≥ 0.90, Critical_Asset=True | 금융 핵심 자산에서 발견된 고위험 예비 취약점 |
| **Confirmed Exploited** | KEV=True | 실제 공격 확인, 즉시 긴급 패치 필요 |
| **High Probability** | KEV=False, EPSS_percentile ≥ 0.80 | 공격 가능성 높음, 계획적 패치 필요 |
| **Standard Monitoring** | 그 외 | 정기 모니터링 대상 |

**우선순위 순서:** Immediate Watchlist > Confirmed Exploited > High Probability > Standard Monitoring

---

## 금융권 환경에서 이 방식이 타당한 이유

1. **규제 환경**: 금융권 보안 환경에서는 취약점 발견 후 신속한 조치와 지속적인 모니터링이 요구됩니다. KEV 등재만을 기다릴 경우 실제 공격 대응이 늦어질 수 있습니다.

2. **핵심 자산 집중**: 금융 인프라(API Gateway, MFT, VPN, IAM)는 공격자의 주요 초기 침투 대상이며, 해당 키워드를 `Critical_Asset_flag`로 특화하여 반영했습니다.

3. **사고 비용**: 금융기관의 데이터 유출 사고는 직접적인 금전 피해 외에도 규제 제재, 신뢰도 손상, 시스템 복구 비용이 매우 큽니다. 선제 대응 비용이 훨씬 낮습니다.

4. **빠른 EPSS 업데이트 주기**: EPSS는 매일 업데이트되므로, KEV보다 훨씬 빠르게 위협 변화를 감지할 수 있습니다.

---

## 실행 방법

### 사전 요구사항

```bash
pip install opensearch-py pandas openpyxl requests
```

OpenSearch가 로컬에서 실행 중이어야 하며, `vulnerability_cve` 인덱스에 NVD 데이터가 적재되어 있어야 합니다.

### 실행

```bash
cd "Risk Analysis Module"
python "Weight Tuning/WangJinling/epss_kev_gap_early_warning.py"
```

---

## 출력 파일 설명

| 파일 | 설명 |
|------|------|
| `wangjinling_epss_kev_gap_result.csv` | 전체 분석 결과 CSV |
| `wangjinling_epss_kev_gap_result.xlsx` | 전체 분석 결과 Excel (컬럼 서식 포함) |

출력 파일에는 다음 필드가 포함됩니다:
`host`, `asset_type`, `port`, `service`, `matched_technology`, `cpe_23`, `cve_id`, `cvss_score`, `cvss_norm`, `epss_percentile`, `in_kev`, `knownRansomwareCampaignUse`, `cwe_ids`, `critical_asset_flag`, `auth_or_rce_flag`, `internet_exposed_flag`, `base_exploitability_score`, `kev_gap_bonus`, `financial_impact_score`, `final_score`, `priority_category`, `action_plan`, `reason`

---

## 기대 결과

- **Immediate Watchlist**: EPSS 상위권이면서 금융 핵심 자산(WSO2, GoAnywhere, Citrix 등)에서 발견된 취약점이 KEV 등재 전에 먼저 식별됩니다.
- **기존 모델 대비**: KEV=True 중심 모델에서는 놓칠 수 있는 고위험 예비 취약점들이 상위에 노출됩니다.
- **금융 선제 대응**: KEV 발표 이전 또는 등재 지연 구간에서 패치 계획을 더 빠르게 검토할 수 있어, 공격 표면을 선제적으로 줄이는 데 도움이 됩니다.
