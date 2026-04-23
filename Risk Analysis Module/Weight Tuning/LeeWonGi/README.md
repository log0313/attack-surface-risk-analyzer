cwe 추가를 위해 수정한 nvd_to_opensearch.py 첨부.

## 1. 가중치 산정 논리 (Scoring Methodology)
본 모델은 다음과 같은 수식을 통해 리스크 점수를 산출함.

$$
Score = (CVSS \times W_{1}) + (KEV_{weight} \times W_{2}) + (CWE_{bank} \times W_{3}) + (EPSS \times W_{4})
$$

### CVSS(W1)를 기준점(1.0)으로 고정한 이유
가중치 최적화 과정에서 모든 변수를 동시에 변경할 경우 모델의 수렴이 어렵고 기준점이 모호해지기 때문에 전 세계적으로 통용되는 취약점의 정적 심각도를 나타내는 표준 지표인 CVSS를 1.0으로 고정함으로써
다른 동적 지표들(KEV, EPSS 등)이 기본 심각도 대비 몇 배의 중요도를 갖는지를 직관적으로 파악할 수 있도록 함.

### 가중치 부여 이유
금융권 기술 스택은 고정되어 있지 않고 위협 환경은 매일 변하기 때문에 가장 최신의 위협 흐름을 반영하는 EPSS에 최고 가중치를 줌으로써, 모델이 최신 공격 트렌드에 즉각적으로 반응하도록 설계.
KEV에 따라 이미 사고가 난 지점을 보기 보다는 cwe리스트에 금융 인프라에서 치명적인 것들을 담아두고 거기에 가중치를 더 줌으로써, 금융 산업 특화적 위험을 반영할 수 있도록 함.
필요에 따라 cwe에 중요하다고 생각하는 지표를 넣어서 조절도 가능.

## 2. 코드 상의 가중치 튜닝 방식 (Mechanism)
본 모델은 초기 가중치를 최소값으로 설정한 후, 전체 CVE 데이터베이스에서 타겟 취약점(Target CVE)을 포함한 5,000개의 샘플 데이터를 무작위로 추출하여 시뮬레이션을 수행함.
가중치 튜닝의 핵심 목표는 모든 타겟 취약점이 상위권에 포함되는 최소한의 순위 경계선(Cut-off Rank)을 식별하는 것이며, 반복적인 피드백 루프(1000회)를 통해 해당 분석 범위(Alerts)를 최소화함으로써 보안 피로도를 줄이고 탐지 정밀도를 극대화하도록 설계됨.

## 3. 실행 결과
<img width="483" height="578" alt="image" src="https://github.com/user-attachments/assets/33a339b0-d30a-4c99-b7dc-517de38c9032" /> 1번 실행결과

<img width="1000" height="600" alt="final_optimization_clean" src="https://github.com/user-attachments/assets/0a6098c5-ccec-496c-a4c2-8890811fb668" />
final_optimization_clean.png의 경우 붉은색 점 (Scatter Points)은 최적화 시뮬레이션 과정 중 특정 시점(50회 단위)에서 측정된 분석 필요 범위(Alerts)의 실제 값.
붉은색 굵은 선 (Solid Line)은 최적화 추세선 (Trend Line)으로 개별 점들의 변동성을 보정하여 알고리즘이 전체적으로 어느 방향으로 수렴 하고 있는지를 보여주는 4차 다항식 추세선.


<img width="695" height="995" alt="image" src="https://github.com/user-attachments/assets/2cb54a67-be48-48a8-8cf9-190ed3fbb27e" />
이후 scan_report_simulated_real.json으로 만들어진 가중치로 테스트 해 볼 수 있도록 함.
