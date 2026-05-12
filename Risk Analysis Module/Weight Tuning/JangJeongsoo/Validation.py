import pandas as pd
import numpy as np
import os
import urllib3
from opensearchpy import OpenSearch
import matplotlib.pyplot as plt
import warnings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# 그래프 한글 폰트 설정
plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False

# ══════════════════════════════════════════════════════════════
# 1. 설정 및 상수
# ══════════════════════════════════════════════════════════════
VALIDATION_SAMPLE_SIZE = 20000
VALIDATION_SEED = 1234

# Weight 50 기준 임계값
MED_THRESHOLD = 0.243
CRIT_THRESHOLD = 0.844

BANK_CRITICAL_CWES = [
    "CWE-89", "CWE-78", "CWE-287", "CWE-306", "CWE-502",
    "CWE-269", "CWE-284", "CWE-285", "CWE-639", "CWE-327",
    "CWE-326", "CWE-311", "CWE-918", "CWE-611", "CWE-434",
    "CWE-1104", "CWE-494"
]


# ══════════════════════════════════════════════════════════════
# 2. 데이터 수집 & 전처리
# ══════════════════════════════════════════════════════════════
def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=(
            os.environ.get("OPENSEARCH_USER", "admin"),
            os.environ.get("OPENSEARCH_PASS", "VulnScanner_2026!@#"),
        ),
        use_ssl=True, verify_certs=False, ssl_show_warn=False,
    )


def fetch_validation_data(client: OpenSearch) -> pd.DataFrame:
    print(f"[*] Validation 데이터 {VALIDATION_SAMPLE_SIZE}건 추출 중... (Seed: {VALIDATION_SEED})")
    query = {
        "size": VALIDATION_SAMPLE_SIZE,
        "query": {
            "function_score": {
                "query": {"match_all": {}},
                "random_score": {"seed": VALIDATION_SEED, "field": "_seq_no"},
                "boost_mode": "replace",
            }
        },
    }
    response = client.search(index="vulnerability_cve", body=query)
    df = pd.DataFrame([h["_source"] for h in response["hits"]["hits"]])

    df["base_cvss"] = pd.to_numeric(df["cvss_score"], errors="coerce").fillna(0).clip(0, 10)
    df["base_epss"] = pd.to_numeric(df.get("epss_percentile", 0), errors="coerce").fillna(0).clip(0, 1)
    df["flag_poc"] = df["has_poc"].fillna(False).astype(int)
    df["flag_cwe"] = df["cwes"].apply(
        lambda x: 1 if isinstance(x, list) and any(c in x for c in BANK_CRITICAL_CWES) else 0
    )
    df["target_kev"] = df["in_kev"].fillna(False).astype(int)
    return df


# ══════════════════════════════════════════════════════════════
# 3. 모델 수식 적용 (Weight 50 최적화 수식)
# ══════════════════════════════════════════════════════════════
def apply_ml_formula(df: pd.DataFrame) -> pd.DataFrame:
    z = (
            -5.9571
            + (0.1744 * df["base_cvss"])
            + (5.6841 * df["base_epss"])
            + (0.7553 * df["flag_poc"])
            + (0.2420 * df["flag_cwe"])
    )
    df["ml_prob"] = 1 / (1 + np.exp(-z))
    return df


# ══════════════════════════════════════════════════════════════
# 4. 시각화 (확률 분포 그래프)
# ══════════════════════════════════════════════════════════════
def plot_distribution(df: pd.DataFrame):
    y_true = df["target_kev"].values
    prob = df["ml_prob"].values

    score_nonkev = prob[y_true == 0]
    score_kev = prob[y_true == 1]

    plt.figure(figsize=(10, 7))
    bins = np.linspace(0, 1, 50)

    # 히스토그램 그리기
    plt.hist(score_nonkev, bins=bins, alpha=0.6, color="steelblue",
             label=f"Non-KEV (n={len(score_nonkev):,})", density=True)
    plt.hist(score_kev, bins=bins, alpha=0.7, color="#e74c3c",
             label=f"KEV     (n={len(score_kev):,})", density=True)

    # 임계값 수직선 긋기
    plt.axvline(MED_THRESHOLD, color="orange", linestyle="--", lw=5,
                label=f"잠재 위협 경계 ({MED_THRESHOLD * 100:.1f}점)")
    plt.axvline(CRIT_THRESHOLD, color="red", linestyle="-", lw=5,
                label=f"고위험군 경계 ({CRIT_THRESHOLD * 100:.1f}점)")

    # 텍스트 박스

    plt.xlabel("위협도 확률", fontsize=25)
    plt.ylabel("밀도", fontsize=25)
    plt.xticks(fontsize=20)
    plt.yticks(fontsize=20)
    plt.legend(loc="upper center", fontsize=20)
    plt.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig("validation_distribution.png", dpi=150)
    print("\n[*] 시각화 저장 완료: validation_distribution.png")
    plt.show()


# ══════════════════════════════════════════════════════════════
# 5. 검증 리포트 출력 및 실행
# ══════════════════════════════════════════════════════════════
def run_validation():
    client = get_client()
    df = fetch_validation_data(client)
    df = apply_ml_formula(df)

    total_vulns = len(df)
    total_kevs = df["target_kev"].sum()

    print("\n" + "=" * 80)
    print(f"📊 [Validation 데이터 요약] 총 취약점: {total_vulns:,}건 | 전체 KEV(정답): {total_kevs:,}건")
    print("=" * 80)

    # 1. Critical 결과
    crit_mask = df["ml_prob"] >= CRIT_THRESHOLD
    total_over_crit = crit_mask.sum()
    kev_over_crit = df.loc[crit_mask, "target_kev"].sum()
    prec_crit = (kev_over_crit / total_over_crit * 100) if total_over_crit > 0 else 0
    top_pct_crit = (total_over_crit / total_vulns) * 100

    print(f"🚨 [위험도 {CRIT_THRESHOLD * 100:.1f}점 이상 (Critical) 탐지 성능]")
    print(f"  - 분류된 총 취약점 수 : {total_over_crit:,}건 (상위 {top_pct_crit:.2f}%)")
    print(f"  - 그 중 실제 진성 KEV : {kev_over_crit:,}건")
    print(f"  - 알림의 정밀도 (Prec): {prec_crit:.1f}%")
    print("=" * 80)

    # 2. High/Med 결과
    med_mask = df["ml_prob"] >= MED_THRESHOLD
    total_over_med = med_mask.sum()
    kev_over_med = df.loc[med_mask, "target_kev"].sum()
    recall_med = (kev_over_med / total_kevs * 100) if total_kevs > 0 else 0

    print(f"⚠️ [위험도 {MED_THRESHOLD * 100:.1f}점 이상 (High/Med) 탐지 성능]")
    print(f"  - 분류된 총 취약점 수 : {total_over_med:,}건")
    print(f"  - KEV 방어율 (Recall) : {recall_med:.1f}%")
    print("=" * 80)

    # 그래프 띄우기
    plot_distribution(df)


if __name__ == "__main__":
    run_validation()
