### Directory Structure

```text
.
├── conf/                   # Nginx 설정 파일 (Appliance 지문)
│   ├── appliance_mock.conf
│   └── ...
├── docker-compose.yml       # 시뮬레이션 환경 정의
├── AssetScanner.py          # 자산 식별 스캐너 (Requests 기반)
└── README.md

이렇게 모두 같은 root에 두고 실행. request 다운로드 하고 Docker 실행후 터미널에서 
- docker-compose up -d
환경 실행 후 scanner 실행 하면 json 파일이 정상적으로 나옴. 제대로 나왔을 때의 결과가 scan_report_simulated_real.json과 똑같이 나와야 함.

AssetScanner.py의 경우 기존 버전과 차이점이 있는데 일반 도메인 탐색할 때는 httpx 등 오픈소스가 잘 작동하는데 docker에 실행시키면 작동안해서 포트를 고정시키고 request 기반으로 수정.
test_runner.py의 경우 생성한 json 파일에서 타겟 cve 10개가 있는지, 또 전체 cve는 몇개인지가 잘 안나와서 db 매칭 알고리즘을 수정하고 json 파일에 cve가 잘 들었는지 확인할 수 있게 1차적으로 수정. 개선 필요.
