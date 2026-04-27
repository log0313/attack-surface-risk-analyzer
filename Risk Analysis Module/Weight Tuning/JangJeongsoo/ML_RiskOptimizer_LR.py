import pandas as pd
import numpy as np
import os
import urllib3
from opensearchpy import OpenSearch
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
)
import matplotlib.pyplot as plt
import warnings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False


# ══════════════════════════════════════════════════════════════
# 설정값
# ══════════════════════════════════════════════════════════════
CONFIG = {
    "target_recall" : 0.90,
    "max_rounds"    : 50,
    "sample_size"   : 20_000,
    "test_size"     : 0.2,
    "max_iter"      : 1000,
    "kev_weight"    : 10,
    "cwe_bonus"     : 0.05,     # CWE 해당 시 룰 기반 가산점
}

BANK_CRITICAL_CWES = [
    # ── 기본 ───────────────────────────────────
    "CWE-89",   # SQL Injection
    "CWE-78",   # OS Command Injection
    "CWE-287",  # Improper Authentication
    "CWE-306",  # Missing Authentication
    "CWE-502",  # Deserialization

    # ── 인증/접근제어 ───────────────────────────
    "CWE-269",  # Improper Privilege Management
    "CWE-284",  # Improper Access Control
    "CWE-285",  # Improper Authorization
    "CWE-639",  # IDOR

    # ── 암호화 ──────────────────────────────────
    "CWE-327",  # Broken Cryptographic Algorithm
    "CWE-326",  # Inadequate Encryption Strength
    "CWE-311",  # Missing Encryption

    # ── 주입 확장 ───────────────────────────────
    "CWE-918",  # SSRF
    "CWE-611",  # XXE
    "CWE-434",  # Unrestricted File Upload

    # ── 공급망 ──────────────────────────────────
    "CWE-1104", # Unmaintained Third-Party Component
    "CWE-494",  # Download Without Integrity Check
]

# ✅ CWE 제외 — 3개 피처로 축소
FEATURES = ["base_cvss", "base_epss", "flag_poc"]


# ══════════════════════════════════════════════════════════════
# OpenSearch 연결
# ══════════════════════════════════════════════════════════════
def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=(
            os.environ.get("OPENSEARCH_USER", "admin"),
            os.environ.get("OPENSEARCH_PASS", "VulnScanner_2026!@#"),
        ),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False,
    )


# ══════════════════════════════════════════════════════════════
# 데이터 수집 & 전처리
# ══════════════════════════════════════════════════════════════
def fetch_dataset(client: OpenSearch, seed: int) -> pd.DataFrame:
    query = {
        "size": CONFIG["sample_size"],
        "query": {
            "function_score": {
                "query": {"match_all": {}},
                "random_score": {"seed": seed, "field": "_seq_no"},
                "boost_mode": "replace",
            }
        },
    }
    response = client.search(index="vulnerability_cve", body=query)
    df = pd.DataFrame([h["_source"] for h in response["hits"]["hits"]])
    return _preprocess(df)


def _preprocess(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["base_cvss"]  = pd.to_numeric(df["cvss_score"], errors="coerce").fillna(0).clip(0, 10)
    df["base_epss"]  = pd.to_numeric(df.get("epss_percentile", 0), errors="coerce").fillna(0).clip(0, 1)
    df["flag_poc"]   = df["has_poc"].fillna(False).astype(int)

    # CWE는 모델 피처에서 제외 — 룰 기반 보정용으로만 보존
    df["flag_cwe"]   = df["cwes"].apply(
        lambda x: 1 if isinstance(x, list) and any(c in x for c in BANK_CRITICAL_CWES) else 0
    )
    df["target_kev"] = df["in_kev"].fillna(False).astype(int)
    return df


# ══════════════════════════════════════════════════════════════
# 룰 기반 CWE 보정 점수
# ══════════════════════════════════════════════════════════════
def apply_cwe_bonus(model_prob: np.ndarray, flag_cwe: np.ndarray) -> np.ndarray:
    """
    모델 확률(0~1)에 CWE 해당 시 보정값을 가산.
    모델이 학습하지 못한 도메인 지식을 룰로 보완.
    """
    bonus = flag_cwe * CONFIG["cwe_bonus"]
    return np.clip(model_prob + bonus, 0, 1)


# ══════════════════════════════════════════════════════════════
# 임계값 탐색
# ══════════════════════════════════════════════════════════════
def find_best_threshold(y_prob: np.ndarray, y_test: np.ndarray, target_recall: float):
    prec, rec, thr = precision_recall_curve(y_test, y_prob)

    valid_mask = rec[:-1] >= target_recall
    if not valid_mask.any():
        return None, None, None

    best_idx  = np.argmax(prec[:-1][valid_mask])
    return (
        thr[valid_mask][best_idx],
        prec[:-1][valid_mask][best_idx],
        rec[:-1][valid_mask][best_idx],
    )


# ══════════════════════════════════════════════════════════════
# 단일 라운드 학습
# ══════════════════════════════════════════════════════════════
def run_single_round(df: pd.DataFrame, seed: int) -> dict:
    X, y = df[FEATURES], df["target_kev"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=CONFIG["test_size"], random_state=seed, stratify=y
    )

    # CWE 보정용 — 테스트셋 인덱스 기준으로 분리
    cwe_test = df.loc[X_test.index, "flag_cwe"].values

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(
            class_weight={0: 1, 1: CONFIG["kev_weight"]},
            max_iter=CONFIG["max_iter"],
            solver="lbfgs",
            random_state=seed,
        )),
    ])
    pipeline.fit(X_train, y_train)

    # 모델 확률 → CWE 보정 적용
    raw_prob      = pipeline.predict_proba(X_test)[:, 1]
    adjusted_prob = apply_cwe_bonus(raw_prob, cwe_test)

    threshold, precision, recall = find_best_threshold(
        adjusted_prob, y_test, CONFIG["target_recall"]
    )

    if threshold is None:
        return {"success": False}

    roc_auc = roc_auc_score(y_test, adjusted_prob)
    pr_auc  = average_precision_score(y_test, adjusted_prob)
    f1      = 2 * precision * recall / (precision + recall + 1e-9)

    return {
        "success"      : True,
        "pipeline"     : pipeline,
        "threshold"    : threshold,
        "recall"       : recall,
        "precision"    : precision,
        "f1"           : f1,
        "roc_auc"      : roc_auc,
        "pr_auc"       : pr_auc,
        "seed"         : seed,
        "X_test"       : X_test,
        "y_test"       : y_test,
        "cwe_test"     : cwe_test,
        "adjusted_prob": adjusted_prob,
    }


# ══════════════════════════════════════════════════════════════
# 메인 탐색 루프
# ══════════════════════════════════════════════════════════════
def search_best_model(client: OpenSearch):
    print("=" * 60)
    print(f" 목표: KEV Recall ≥ {CONFIG['target_recall']} | "
          f"최대 {CONFIG['max_rounds']} 라운드")
    print(f" 고정 weight={CONFIG['kev_weight']} | "
          f"CWE 보정={CONFIG['cwe_bonus']} (룰 기반)")
    print(f" 모델 피처: {FEATURES}")
    print("=" * 60)

    best_result = None
    history     = []

    for round_idx in range(1, CONFIG["max_rounds"] + 1):
        seed = round_idx * 7 + 42
        print(f"[Round {round_idx:02d}] seed={seed} ", end="", flush=True)

        try:
            df = fetch_dataset(client, seed=seed)
        except Exception as e:
            print(f"추출 실패: {e}")
            continue

        kev_cnt = df["target_kev"].sum()
        print(f"| KEV {kev_cnt}건 ({kev_cnt/len(df)*100:.1f}%) ", end="")

        result = run_single_round(df, seed=seed)

        if result["success"]:
            print(f"| recall={result['recall']:.4f} "
                  f"precision={result['precision']:.4f} "
                  f"f1={result['f1']:.4f}", end="")

            history.append({
                "round"    : round_idx,
                "recall"   : result["recall"],
                "precision": result["precision"],
                "f1"       : result["f1"],
                "roc_auc"  : result["roc_auc"],
            })

            if best_result is None or result["f1"] > best_result["f1"]:
                best_result = result
                print(" ★", end="")
        else:
            print("| recall 미달 ❌", end="")

        print()  # 줄바꿈

    # ── 결과 요약 ──
    print("\n" + "=" * 60)
    print(f" 탐색 완료: {CONFIG['max_rounds']} 라운드")
    if best_result:
        print(f" 최종 선택 모델 (seed={best_result['seed']})")
        print(f"   threshold : {best_result['threshold']:.4f}")
        print(f"   recall    : {best_result['recall']:.4f}")
        print(f"   precision : {best_result['precision']:.4f}")
        print(f"   f1        : {best_result['f1']:.4f}")
        print(f"   ROC-AUC   : {best_result['roc_auc']:.4f}")
        print(f"   PR-AUC    : {best_result['pr_auc']:.4f}")
    else:
        print(" ⚠ 목표 Recall 달성 실패.")
    print("=" * 60)

    return best_result, history


# ══════════════════════════════════════════════════════════════
# 최종 리포트
# ══════════════════════════════════════════════════════════════
def print_final_report(result: dict):
    y_pred = (result["adjusted_prob"] >= result["threshold"]).astype(int)

    print(f"\n[최종 Classification Report | threshold={result['threshold']:.4f}]")
    print(classification_report(result["y_test"], y_pred,
                                target_names=["Non-KEV", "KEV"]))

    lr_model = result["pipeline"].named_steps["lr"]
    coef_raw = lr_model.coef_[0]
    abs_sum  = np.abs(coef_raw).sum()

    print("=" * 55)
    print("🏆 [LR 계수] 피처별 영향력 (CWE 제외 후)")
    print("=" * 55)
    for feat, coef in zip(FEATURES, coef_raw):
        pct   = abs(coef) / abs_sum * 100
        arrow = "▲" if coef > 0 else "▼"
        bar   = "■" * int(pct // 2)
        print(f"  {feat:12} {coef:>8.4f}  {pct:>5.1f}%  {arrow}")
        print(f"  {'':12} {bar}")
    print(f"\n  [룰 기반] flag_cwe 해당 시 +{CONFIG['cwe_bonus']} 가산 (모델 외부)")
    print("=" * 55)


# ══════════════════════════════════════════════════════════════
# 시각화
# ══════════════════════════════════════════════════════════════
def plot_results(result: dict, history: list):
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))  # 3개 → 2×2 레이아웃

    # ── 1. PR Curve ──
    ax = axes[0][0]
    prec, rec, thr = precision_recall_curve(result["y_test"], result["adjusted_prob"])
    ax.plot(rec, prec, color="steelblue", lw=2)
    ax.scatter([result["recall"]], [result["precision"]],
               color="red", zorder=5, s=100, label=f"선택점 (thr={result['threshold']:.3f})")
    ax.axvline(CONFIG["target_recall"], color="orange", linestyle=":",
               label=f"목표 Recall={CONFIG['target_recall']}")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve")
    ax.legend(); ax.grid(True, alpha=0.3)

    # ── 2. 라운드별 Recall / F1 추이 ──
    ax = axes[0][1]
    if history:
        hist_df = pd.DataFrame(history)
        ax.plot(hist_df["round"], hist_df["recall"], marker="o",
                label="Recall", color="steelblue")
        ax.plot(hist_df["round"], hist_df["f1"], marker="s",
                label="F1", color="coral")
        ax.axhline(CONFIG["target_recall"], color="red",
                   linestyle="--", label=f"목표={CONFIG['target_recall']}")
    ax.set_xlabel("Round"); ax.set_ylabel("Score")
    ax.set_title("라운드별 Recall / F1 추이")
    ax.legend(); ax.grid(True, alpha=0.3)

    # ── 3. 피처 계수 ──
    ax = axes[1][0]
    lr_model = result["pipeline"].named_steps["lr"]
    coef_raw = lr_model.coef_[0]
    colors   = ["#e74c3c" if c > 0 else "#3498db" for c in coef_raw]
    bars     = ax.barh(FEATURES, coef_raw, color=colors)
    ax.bar_label(bars, fmt="%.4f", padding=3)
    ax.axvline(0, color="black", lw=0.8)
    ax.set_xlabel("Coefficient")
    ax.set_title("피처별 LR 계수 (CWE 제외)")
    ax.grid(True, alpha=0.3, axis="x")

    # ── 4. 위협도 점수 분포 ──
    ax = axes[1][1]
    y_test       = result["y_test"].values
    adj_prob     = result["adjusted_prob"]

    score_nonkev = adj_prob[y_test == 0]
    score_kev    = adj_prob[y_test == 1]

    bins = np.linspace(0, 1, 40)

    ax.hist(score_nonkev, bins=bins, alpha=0.6, color="steelblue",
            label=f"Non-KEV (n={len(score_nonkev):,})", density=True)
    ax.hist(score_kev, bins=bins, alpha=0.7, color="#e74c3c",
            label=f"KEV     (n={len(score_kev):,})", density=True)

    # 선택된 threshold 표시
    ax.axvline(result["threshold"], color="black", linestyle="--", lw=1.5,
               label=f"threshold={result['threshold']:.3f}")

    # 통계 요약 텍스트
    textstr = (
        f"Non-KEV  평균: {score_nonkev.mean():.3f}\n"
        f"KEV      평균: {score_kev.mean():.3f}\n"
        f"분리도 (Δ): {score_kev.mean() - score_nonkev.mean():.3f}"
    )
    ax.text(0.97, 0.97, textstr, transform=ax.transAxes,
            fontsize=9, verticalalignment="top", horizontalalignment="right",
            bbox=dict(boxstyle="round", facecolor="lightyellow", alpha=0.8))

    ax.set_xlabel("위협도 점수 (adjusted_prob)")
    ax.set_ylabel("밀도 (Density)")
    ax.set_title("위협도 점수 분포 — KEV vs Non-KEV")
    ax.legend(); ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig("lr_recall_optimized.png", dpi=150)
    print("\n[*] 시각화 저장 완료: lr_recall_optimized.png")
    plt.show()


# ══════════════════════════════════════════════════════════════
# 진입점
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    client = get_client()
    best_result, history = search_best_model(client)

    if best_result:
        print_final_report(best_result)
        plot_results(best_result, history)
