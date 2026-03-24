# cpe_matcher.py
from difflib import SequenceMatcher


def check_cpe_similarity(scanned_cpe, nvd_cpe):
    """
    [CPE 유사도 측정 함수]
    스캔된 데이터(Nmap/HTTPX)와 NVD 공식 사전 데이터 간의 문자열 일치율을 계산합니다.
    사용 예: score = check_cpe_similarity("cpe:/a:apache:http_server:2.4.7", "cpe:2.3:a:apache:http_server:2.4.7")
    """
    if not scanned_cpe or not nvd_cpe:
        return 0.0

    # 접두사 및 특수기호 정리 (CPE 2.2 vs 2.3 대응)
    s_clean = (
        scanned_cpe.replace("cpe:/a:", "").replace("cpe:2.3:a:", "").replace(":", " ")
    )
    n_clean = nvd_cpe.replace("cpe:/a:", "").replace("cpe:2.3:a:", "").replace(":", " ")

    return SequenceMatcher(None, s_clean, n_clean).ratio()


# 테스트용 코드 (직접 실행 시에만 작동)
if __name__ == "__main__":
    test_score = check_cpe_similarity(
        "cpe:/a:apache:http_server:2.4.7", "cpe:2.3:a:apache:http_server:2.4.7"
    )
    print(f"매칭 점수: {test_score:.2f}")
