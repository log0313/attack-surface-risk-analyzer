import pandas as pd
import numpy as np
import time
import urllib3
from opensearchpy import OpenSearch
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import precision_recall_curve, confusion_matrix
import warnings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# ══════════════════════════════════════════════════════════════
# 1. 설정 및 상수
# ══════════════════════════════════════════════════════════════
TARGET_RECALL = 0.90  # [High/Med 기준] 목표 방어율 90%
TARGET_CRITICAL_PRECISION = 0.30  # [Critical 기준] 목표 정밀도 30%
TEST_SIZE = 0.2

# 튜닝해볼 가중치(kev_weight) 리스트: 10부터 100까지 10단위
WEIGHTS_TO_TEST = list(range(10, 110, 10))

FEATURES = ["base_cvss", "base_epss", "flag_poc", "flag_cwe"]

BANK_CRITICAL_CWES = [
    "CWE-89", "CWE-78", "CWE-287", "CWE-306", "CWE-502",
    "CWE-269", "CWE-284", "CWE-285", "CWE-639", "CWE-327",
    "CWE-326", "CWE-311", "CWE-918", "CWE-611", "CWE-434",
    "CWE-1104", "CWE-494"
]


# ══════════════════════════════════════════════════════════════
# 2. OpenSearch 대용량 데이터 추출 (Scroll API)
# ══════════════════════════════════════════════════════════════
def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=("admin", "VulnScanner_2026!@#"),
        use_ssl=True, verify_certs=False, ssl_show_warn=False,
    )


def fetch_all_data(client: OpenSearch) -> pd.DataFrame:
    print("[*] OpenSearch에서 전체 데이터를 Scroll 방식으로 추출 중... (1회만 실행)")
    start_time = time.time()
    query = {"query": {"match_all": {}}}
    response = client.search(index="vulnerability_cve", body=query, scroll='2m', size=10000)

    sid = response['_scroll_id']
    hits = response['hits']['hits']
    all_hits = []

    while len(hits) > 0:
        all_hits.extend(hits)
        response = client.scroll(scroll_id=sid, scroll='2m')
        sid = response['_scroll_id']
        hits = response['hits']['hits']

    df = pd.DataFrame([h['_source'] for h in all_hits])
    client.clear_scroll(scroll_id=sid)
    print(f"[*] 추출 완료! 총 {len(df):,}건 (소요 시간: {time.time() - start_time:.1f}초)")
    return df


def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    df["base_cvss"] = pd.to_numeric(df["cvss_score"], errors="coerce").fillna(0).clip(0, 10)
    df["base_epss"] = pd.to_numeric(df.get("epss_percentile", 0), errors="coerce").fillna(0).clip(0, 1)
    df["flag_poc"] = df["has_poc"].fillna(False).astype(int)
    df["flag_cwe"] = df["cwes"].apply(
        lambda x: 1 if isinstance(x, list) and any(c in x for c in BANK_CRITICAL_CWES) else 0
    )
    df["target_kev"] = df["in_kev"].fillna(False).astype(int)
    return df


# ══════════════════════════════════════════════════════════════
# 3. 메인 그리드 서치 루프
# ══════════════════════════════════════════════════════════════
def run_massive_grid_search():
    client = get_client()
    raw_df = fetch_all_data(client)
    df = preprocess_data(raw_df)

    X = df[FEATURES]
    y = df["target_kev"]
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=TEST_SIZE, random_state=42, stratify=y)

    total_val_kevs = y_val.sum()

    print("\n" + "=" * 105)
    print(f"🚀 [대규모 듀얼 임계값 최적화] Val 데이터: {len(X_val):,}건 (정답 KEV: {total_val_kevs:,}건)")
    print("=" * 105)

    results = []
    formulas = {}  # 가중치별 산출된 최종 Z 수식을 저장할 딕셔너리

    for weight in WEIGHTS_TO_TEST:
        print(f" >> 가중치(kev_weight) = {weight:<3} 평가 중...", end="")

        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("lr", LogisticRegression(class_weight={0: 1, 1: weight}, max_iter=2000, solver="lbfgs", random_state=42))
        ])
        pipeline.fit(X_train, y_train)

        # Train 셋 기반 임계값 계산
        train_prob = pipeline.predict_proba(X_train)[:, 1]
        prec, rec, thr = precision_recall_curve(y_train, train_prob)

        # 1. High/Med Threshold (Recall >= 90% 구간에서 Precision이 가장 높은 점)
        valid_rec_mask = rec[:-1] >= TARGET_RECALL
        if not valid_rec_mask.any():
            print(" [실패]")
            continue
        hm_idx = np.argmax(prec[:-1][valid_rec_mask])
        hm_threshold = thr[valid_rec_mask][hm_idx]

        # 2. Critical Threshold (Precision >= 30% 구간에서 Recall이 가장 높은 점)
        valid_prec_mask = prec[:-1] >= TARGET_CRITICAL_PRECISION
        if valid_prec_mask.any():
            crit_idx = np.argmax(rec[:-1][valid_prec_mask])
            crit_threshold = thr[valid_prec_mask][crit_idx]
        else:
            crit_threshold = thr[-1]  # 30% 도달 실패 시 가장 높은 점수 사용

        # Val 셋 검증
        val_prob = pipeline.predict_proba(X_val)[:, 1]

        # High/Med 결과
        hm_preds = (val_prob >= hm_threshold).astype(int)
        hm_tp = np.sum((hm_preds == 1) & (y_val == 1))
        hm_fp = np.sum((hm_preds == 1) & (y_val == 0))
        hm_alerts = hm_tp + hm_fp
        hm_val_recall = (hm_tp / total_val_kevs) * 100 if total_val_kevs > 0 else 0

        # Critical 결과
        crit_preds = (val_prob >= crit_threshold).astype(int)
        crit_tp = np.sum((crit_preds == 1) & (y_val == 1))
        crit_fp = np.sum((crit_preds == 1) & (y_val == 0))
        crit_alerts = crit_tp + crit_fp
        crit_val_prec = (crit_tp / crit_alerts) * 100 if crit_alerts > 0 else 0
        crit_val_recall = (crit_tp / total_val_kevs) * 100 if total_val_kevs > 0 else 0

        # 스캐너 적용용 실제 계수(Raw Coefficient) 및 Bias 역산
        scaler = pipeline.named_steps["scaler"]
        lr_model = pipeline.named_steps["lr"]

        coef_raw = lr_model.coef_[0] / scaler.scale_
        bias_raw = lr_model.intercept_[0] - np.sum((lr_model.coef_[0] * scaler.mean_) / scaler.scale_)

        # CWE 비중 계산
        cwe_importance = (abs(coef_raw[FEATURES.index("flag_cwe")]) / np.abs(coef_raw).sum()) * 100

        # 수식(Formula) 문자열 생성
        formula_str = f"z = {bias_raw:.4f}"
        for feat, coef in zip(FEATURES, coef_raw):
            sign = "+" if coef >= 0 else "-"
            formula_str += f" {sign} ({abs(coef):.4f} * {feat})"

        formulas[weight] = formula_str

        results.append({
            "Weight": weight,
            "CWE_비중": f"{cwe_importance:.1f}%",
            "Med_Thr": f"{hm_threshold:.3f}",
            "Med_Recall": f"{hm_val_recall:.1f}%",
            "Med_Alerts": f"{hm_alerts:,}",
            "Crit_Thr": f"{crit_threshold:.3f}",
            "Crit_Prec": f"{crit_val_prec:.1f}%",
            "Crit_Recall": f"{crit_val_recall:.1f}%",
            "Crit_Alerts": f"{crit_alerts:,}"
        })
        print(" [완료]")

    # ══════════════════════════════════════════════════════════════
    # 4. 최종 결과 및 수식 출력
    # ══════════════════════════════════════════════════════════════
    res_df = pd.DataFrame(results)
    print("\n" + "=" * 105)
    print("🏆 [가중치별 듀얼 티어(High/Med & Critical) 검증 통합 비교표]")
    print("=" * 105)
    print(res_df.to_string(index=False))

    print("\n" + "=" * 105)
    print("💡 [가중치별 스캐너 탑재용 Z 수식 (Python)]")
    print("=" * 105)
    for weight in WEIGHTS_TO_TEST:
        if weight in formulas:
            print(f" [Weight {weight:<3}] {formulas[weight]}")
    print("=" * 105)


if __name__ == "__main__":
    run_massive_grid_search()
