# 실행 순서: nvd_manager.py -> nvd_to_opensearch.py -> sync_threat_intel.py

# nvd_manager.py
- nvd에서 cve를 다운로드하는 파일입니다. 실행시 최하단에 메뉴를 고르면 되고, 최초 실행이라면 manager.download_all() 부분을 활성화하고 manager.update_recent(days=7) 부분을 비활성화하면 됩니다.
- api키가 없으면 다운로드 호출 대기시간이 길어지기 때문에 우선 개인적으로 발급받은 api키를 넣어뒀습니다. 발급은 https://nvd.nist.gov/developers/request-an-api-key 에서 가능합니다.
- update를 상정하고 만들었기 때문에 최초 실행시에는 cve_data_full.json파일이 만들어지고, 이후 update메뉴로 다운로드한다면 cve_data_update.json파일이 생성됩니다.

# nvd_to_opensearch.py
- 다운로드한 cve를 db에 적재하는 파일입니다. opensearch 환경이 구성되어야 하며, 테스트는 docker에서 진행했습니다. 주의할 점은 비밀번호가 너무 쉬우면 opensearch 컨테이너가 바로 종료됩니다.
- cpe는 'vendor:product:version'의 형식으로 db에 저장됩니다.
- 최하단에 TARGET_FILE명을 nvd_manager.py를 실행할 때 생성한 파일명과 일치시켜야 합니다.

# sync_threat_intel.py
- EPSS와 KEV를 다운로드해 db에 업데이트하는 파일입니다. nvd_to_opensearch.py에서 미리 만들어둔 빈 필드를 사용합니다.
- 별도의 파일을 사용하지 않으며, db만 정상적으로 동작하고 있으면 실행 가능합니다.

# test_runner.py
- 테스트 용도로 만든 파일입니다. AssetScanner로 확인한 포트와 기술 스택의 정보를 토대로 DB에 적재된 cpe와 매칭한 결과를 보여줍니다.
- Opensearch에서 검색한 데이터를 가지고 cpe_matcher를 사용해 유사도가 높은 CVE를 출력합니다. 검색어와 실제 불러온 CVE의 cpe를 비교할 수 있게 EPSS score 옆에 DB의 cpe를 표기하도록 했습니다.
