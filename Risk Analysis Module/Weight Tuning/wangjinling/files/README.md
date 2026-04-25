1. 개요
Weight Tuning 작업에서는 기존의 CVSS, EPSS, KEV 단순 가중치 방식과 다르게  EPSS는 높지만 아직 KEV에는 등재되지 않은 취약점을 먼저 확인하는 방식으로 모델을 구성했습니다.
일반적으로 KEV에 포함된 취약점은 이미 실제 악용 사례가 확인된 것이기 때문에 중요합니다.  
하지만 KEV는 실제 공격 증거가 확인된 뒤에 등재되므로, 공격 가능성이 높아지는 시점보다 늦게 반영될 수 있습니다.
그래서 저는 금융권 환경에서는 KEV 등재 여부만 보는 것보다,  EPSS percentile이 높고 금융 핵심 자산에서 발견된 취약점을 미리 Watchlist에 올리는 것이 더 적절하다고 판단했습니다.
2.추가한 파일
Risk Analysis Module/ docker-compose-opensearch.yml
기존 docker-compose.yml은 테스트용 nginx 자산만 실행하기 때문에,CVE 데이터를 저장하고 조회할 OpenSearch 환경이 따로 필요했습니다.그래서 docker-compose-opensearch.yml을 추가하여 localhost:9200에서 OpenSearch를 실행할 수 있도록 했습니다
3.점수 계산 방식
최종 점수는 다음 세 부분으로 계산했습니다.
Final Score =Base Exploitability Score+ KEV Gap Bonus+ Financial Impact Score
최종 점수는 최대 100점으로 제한했습니다：Final Score = min(100, total_score)

(1)Base Exploitability Score:
기본 위험도는 CVSS, EPSS, KEV 여부를 사용합니다.
Base Exploitability Score =CVSS_norm × 25 + EPSS_percentile × 35 + KEV_flag × 15
CVSS_norm = CVSS / 10
EPSS_percentile = EPSS 백분위 값
KEV_flag = KEV 포함 시 1, 아니면 0
EPSS에 비교적 높은 비중을 둔 이유는 “이미 악용된 취약점”뿐만 아니라 “앞으로 악용될 가능성”도 중요하게 보기 때문입니다.
(2)KEV Gap Bonus
EPSS_percentile >= 0.95 and KEV=False  → +20
EPSS_percentile >= 0.90 and KEV=False  → +15
EPSS_percentile >= 0.80 and KEV=False  → +10
otherwise                              → +0
EPSS는 높지만 아직 KEV에는 없는 취약점에 추가 점수를 줍니다.
KEV는 실제 악용이 확인된 뒤 등재되기 때문에,금융권에서는 KEV 등재 전이라도 EPSS가 높은 취약점을 미리 확인할 필요가 있다고 판단했습니다.
(3)Financial Impact Score
Financial Impact Score = Critical_Asset_flag × 10+ Auth_or_RCE_flag × 8 + Internet_Exposed_flag × 7 + Ransomware_flag × 5

Critical_Asset_flag
- API Gateway, MFT, VPN, Firewall, IAM 등 금융 핵심 자산이면 1
Auth_or_RCE_flag
- 인증 우회, RCE, SQL Injection, Command Injection 등이면 1
Internet_Exposed_flag
- HTTP/HTTPS 서비스 또는 외부 노출 포트이면 1
Ransomware_flag
- knownRansomwareCampaignUse 값이 Known이면 1
(4)Priority Category
Immediate Watchlist
- EPSS가 높지만 KEV에는 없는 취약점
- 선제 대응 대상
Confirmed Exploited
- KEV에 등재된 취약점
- 실제 악용 확인 대상
High Probability
- KEV에는 없지만 EPSS가 0.80 이상인 취약점
Standard Monitoring
- 일반 모니터링 대상
4.출력 결과
wangjinling_epss_kev_gap_result.csv
wangjinling_epss_kev_gap_result.xlsx
<img width="2172" height="1632" alt="123" src="https://github.com/user-attachments/assets/dc52a7ba-59f3-4210-9a71-51e1f8b5f549" />
<img width="1798" height="1298" alt="1234" src="https://github.com/user-attachments/assets/f98100c8-42aa-4cb8-8707-ff49a5cf3cac" />

