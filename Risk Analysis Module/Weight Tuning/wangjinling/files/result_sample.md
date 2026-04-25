# EPSS-KEV Gap Based Early Warning Model — 결과 샘플 보고서

> 이 문서는 `scan_report_simulated_real.json` 기반으로 분석했을 때 기대되는 출력 예시입니다.  
> OpenSearch에 NVD + EPSS + KEV 데이터가 정상 적재된 환경을 가정합니다.  
> 아래 수치는 실제 실행 결과가 아니라 모델 동작 방식을 설명하기 위한 예시입니다.

---

## Priority Category 집계 (예시)

```
█████████████████████████████████████████████████████████████████
  📊 Priority Category 집계
█████████████████████████████████████████████████████████████████
  Immediate Watchlist          :   14 건
  Confirmed Exploited          :    8 건
  High Probability             :   22 건
  Standard Monitoring          :   51 건
  전체 식별 취약점               :   95 건
█████████████████████████████████████████████████████████████████
```

---

## Top CVE Ranking 예시 (상위 10건)

| 순위 | Category | CVE ID | Final Score | KEV | EPSS | Gap Bonus | Technology |
|------|----------|--------|-------------|-----|------|-----------|------------|
| 1 | **Immediate Watchlist** | CVE-2023-34362 | **97.5** | ❌ | 0.99 | +20 | Progress:moveit_transfer |
| 2 | **Immediate Watchlist** | CVE-2023-0669 | **95.2** | ❌ | 0.97 | +20 | Fortra:goanywhere_mft |
| 3 | **Immediate Watchlist** | CVE-2023-4966 | **93.8** | ❌ | 0.96 | +20 | Citrix:netscaler_adc |
| 4 | **Immediate Watchlist** | CVE-2024-3400 | **92.1** | ❌ | 0.95 | +20 | Paloaltonetworks:pan-os |
| 5 | **Confirmed Exploited** | CVE-2021-44228 | **90.0** | ✅ | 0.98 | +0 | apache:log4j-core |
| 6 | **Confirmed Exploited** | CVE-2022-29464 | **88.5** | ✅ | 0.96 | +0 | WSO2:api_manager |
| 7 | **Confirmed Exploited** | CVE-2022-40684 | **87.2** | ✅ | 0.94 | +0 | Fortinet:fortios |
| 8 | **High Probability** | CVE-2022-1388 | **81.4** | ❌ | 0.87 | +10 | F5:big-ip |
| 9 | **High Probability** | CVE-2017-5638 | **79.8** | ❌ | 0.85 | +10 | Apache:struts |
| 10 | **High Probability** | CVE-2025-61757 | **76.3** | ❌ | 0.82 | +10 | oracle:identity_management_suite |

---

## Immediate Watchlist 예시

> **핵심**: KEV에 아직 없지만, EPSS가 매우 높고 금융 핵심 자산에서 발견됨 → 선제 대응 골든 타임

### CVE-2023-34362 — MOVEit Transfer SQL Injection

```
host                    : mft1.vulnweb.com
asset_type              : Managed File Transfer
port                    : 8081
service                 : http
matched_technology      : Progress:moveit_transfer:*
cve_id                  : CVE-2023-34362
cvss_score              : 9.8
cvss_norm               : 0.98
epss_percentile         : 0.9942
in_kev                  : False
critical_asset_flag     : 1
auth_or_rce_flag        : 1
internet_exposed_flag   : 1
base_exploitability_score : 62.99
kev_gap_bonus           : 20
financial_impact_score  : 25
final_score             : 97.5 ★
priority_category       : Immediate Watchlist

action_plan:
  - KEV 등재 전 선제 대응 필요
  - 24~72시간 내 영향도 확인
  - 임시 차단, WAF rule, 접근제어 적용 검토
  - KEV 등재 여부 지속 모니터링

reason:
  High EPSS but not yet listed in KEV |
  Possible KEV delay risk |
  Critical financial asset |
  Internet-exposed service |
  Authentication bypass or RCE pattern |
  High exploitation probability based on EPSS |
  High CVSS severity
```

**분석 포인트:**
- EPSS 99.4%는 전체 CVE 중 상위 0.6% 수준 → 공격자들이 이미 무기화 단계
- SQL Injection + Pre-auth → `auth_or_rce_flag=1`로 `financial_impact_score` 최대
- 포트 8081 HTTP 노출 → `internet_exposed_flag=1`
- KEV Gap Bonus +20점: 아직 KEV에 없지만 KEV 등재 임박 가능성 매우 높음

---

### CVE-2023-0669 — GoAnywhere MFT Pre-auth RCE

```
host                    : mft2.vulnweb.com
asset_type              : Managed File Transfer
port                    : 8081
service                 : http
matched_technology      : Fortra:goanywhere_mft:*
cve_id                  : CVE-2023-0669
cvss_score              : 7.2
cvss_norm               : 0.72
epss_percentile         : 0.9741
in_kev                  : False
critical_asset_flag     : 1
auth_or_rce_flag        : 1
internet_exposed_flag   : 1
base_exploitability_score : 59.04
kev_gap_bonus           : 20
financial_impact_score  : 25
final_score             : 95.2
priority_category       : Immediate Watchlist
```

**분석 포인트:**
- CVSS 7.2로 단독으로는 중간 위험으로 분류될 수 있음
- 그러나 EPSS 97.4% + Pre-auth RCE + MFT 자산 + Gap Bonus +20 조합으로 **최상위 위험 식별**
- 기존 CVSS 중심 모델이라면 순위가 낮았을 것 → 본 모델의 차별점 명확히 드러남

---

## Confirmed Exploited 예시

> KEV=True → 이미 실제 공격 발생 확인, 즉시 긴급 패치 필요

### CVE-2021-44228 — Log4Shell

```
host                    : banking.vulnweb.com
asset_type              : Core Framework (Log4j)
port                    : 8080
service                 : http
matched_technology      : apache:log4j-core:2.14.1
cve_id                  : CVE-2021-44228
cvss_score              : 10.0
cvss_norm               : 1.00
epss_percentile         : 0.9781
in_kev                  : True
critical_asset_flag     : 1
auth_or_rce_flag        : 1
internet_exposed_flag   : 1
base_exploitability_score : 72.23
kev_gap_bonus           : 0   ← KEV=True이므로 Gap Bonus 없음
financial_impact_score  : 25
final_score             : 90.0
priority_category       : Confirmed Exploited

action_plan:
  - 긴급 패치 또는 서비스 격리
  - 침해 여부 조사
  - 로그 분석 및 계정/토큰 재발급 검토

reason:
  Already listed in KEV |
  Critical financial asset |
  Internet-exposed service |
  Authentication bypass or RCE pattern
```

---

## High Probability 예시

> EPSS ≥ 0.80, KEV=False → 공격 가능성 높음, 계획적 패치 필요

### CVE-2022-1388 — F5 BIG-IP Auth Bypass

```
cve_id                  : CVE-2022-1388
cvss_score              : 9.8
epss_percentile         : 0.872
in_kev                  : False
kev_gap_bonus           : +10
final_score             : 81.4
priority_category       : High Probability

action_plan:
  - 3~7일 내 패치 계획 수립
  - 외부 노출 여부 재검토
  - 임시 완화 조치 적용
```

---

## Action Plan 요약 예시

| Priority Category | 대응 기한 | 핵심 조치 |
|------------------|----------|----------|
| Immediate Watchlist | **24~72시간** | 임시 차단, WAF rule, 접근제어, KEV 모니터링 |
| Confirmed Exploited | **즉시** | 긴급 패치/격리, 침해 조사, 로그 분석 |
| High Probability | **3~7일** | 패치 계획 수립, 노출 재검토, 완화 조치 |
| Standard Monitoring | 정기 점검 | EPSS/KEV 변화 시 재평가 |

---

## 왜 이 모델이 금융권 선제 대응에 적합한가

### 1. 시간차(Gap) 포착 능력

```
일반 보안팀의 타임라인:
  CVE 공개 ──→ KEV 등재 ──→ 패치 적용
                  ↑
             상황에 따라 지연이 발생할 수 있음

본 모델의 타임라인:
  CVE 공개 ──→ EPSS 급상승 탐지 ──→ 선제 대응
                  ↑
         KEV보다 빠르게 위협 포착 가능
```

### 2. CVSS의 한계 극복

| 상황 | CVSS 순위 | 본 모델 순위 | 실제 위험 |
|------|-----------|-------------|----------|
| CVE-2023-0669 (CVSS 7.2, EPSS 97%) | 낮음 | **1위권** | 극도로 높음 |
| 고CVSS, 저EPSS, 비핵심 자산 | 높음 | 낮음 | 실제 낮음 |

### 3. 금융 규제 환경 대응

- **금융보안원 가이드**: 취약점 발견 후 신속 조치 의무
- KEV 등재를 기다리면 이미 늦을 수 있음
- Immediate Watchlist = **규제 대응 전에 선제적으로 리스트 확보** 가능

### 4. 금융 핵심 자산 특화

MFT(MOVEit, GoAnywhere), VPN, API Gateway, IAM 등은 금융기관의 핵심 인프라로, 단 하나의 취약점 악용으로도 전체 내부망 침투로 이어질 수 있습니다. 이 자산들을 `Critical_Asset_flag`로 우선 식별하여 Financial Impact Score를 높임으로써, 동일한 CVSS 점수라도 금융 인프라의 취약점이 더 높은 최종 점수를 받도록 설계되었습니다.

### 5. 다른 팀 모델과의 보완 관계

| 모델 유형 | 강점 | 약점 |
|----------|------|------|
| CVSS 선형 가중치 | 심각도 표준화 | 실제 악용 여부 미반영 |
| KEV 중심 | 실제 공격 확인 | 사후 대응에 그침 |
| **본 모델 (EPSS-KEV Gap)** | **선제 탐지** | EPSS 데이터 품질에 의존 |

세 모델의 결과를 교차 검토하면 가장 완전한 금융권 취약점 대응 전략을 수립할 수 있습니다.
