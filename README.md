# CAPE 지능형 노이즈 필터(CAPE Intelligent Noise Filter)

CAPE v2 샌드박스의 분석 데이터(`report.json`)에서 윈도우 OS의 정상적인 백그라운드 행위(텔레메트리, 언어팩 로딩 등)와 네트워크 노이즈를 지능적으로 제거해주는 플러그인입니다.

## 핵심 기능
1. **전방위적 행위/네트워크 필터링:** 레지스트리, 파일, 뮤텍스, 명령어, DNS, IP, HTTP 요청 등 11가지 핵심 지표에서 노이즈 제거.
2. **안전한 데이터 격리 (Safe Filtering):** 필터링된 데이터를 삭제하지 않고 `report.json` 내 `filtered_artifacts` 로 이동하여 원본 보존.
3. **자동 베이스라인 생성 (`auto_baseline.py`):** 명령어 한 줄로 깨끗한 VM 분석 결과에서 수천 개의 정상 행위 룰을 자동으로 학습.

## 설치 방법 (Installation)

이 플러그인은 CAPE v2가 설치된 리눅스 호스트 시스템(`/opt/CAPEv2`)에 직접 복사하여 적용합니다.

**1. 파일 복사**
배포된 파일들을 CAPE의 각 디렉터리에 복사하고 권한을 설정합니다.

```bash
# 프로세싱 모듈 복사
sudo cp noise_filter.py /opt/CAPEv2/modules/processing/
sudo cp whitelist.yaml /opt/CAPEv2/modules/processing/

# 자동화 스크립트 복사
sudo cp auto_baseline.py /opt/CAPEv2/utils/

# 권한 설정 (cape 유저)
sudo chown cape:cape /opt/CAPEv2/modules/processing/noise_filter.py
sudo chown cape:cape /opt/CAPEv2/modules/processing/whitelist.yaml
sudo chown cape:cape /opt/CAPEv2/utils/auto_baseline.py
sudo chmod +x /opt/CAPEv2/utils/auto_baseline.py
```

**2. 모듈 활성화 (`processing.conf`)**
CAPE의 프로세싱 설정 파일(`/opt/CAPEv2/conf/processing.conf`) 맨 아래에 필터 모듈을 활성화하는 구문을 추가합니다.

```ini
[noise_filter]
enabled = yes
```

**3. 서비스 재시작**
설정 적용을 위해 CAPE 프로세스 데몬을 재시작합니다.
```bash
sudo systemctl restart cape-processor.service
```

## 운영 가이드 (Usage)

### 1단계: 베이스라인(Baseline) 수집
각 환경(회사망)마다 정상 윈도우 행위가 다릅니다. 설치 직후 가장 먼저 사내 맞춤형 베이스라인을 생성해야 합니다.

1. CAPE 웹 인터페이스나 CLI를 통해 **아무 악성코드도 넣지 않은 빈 분석(Clean Run)**을 5분간 진행합니다.
2. 분석이 완료되면 해당 Task ID(예: `15`)를 확인합니다.
3. 다음 명령어를 실행하여 베이스라인을 추출합니다.

```bash
cd /opt/CAPEv2
sudo -u cape python3 utils/auto_baseline.py 15
```
*완료되면 `whitelist.yaml`에 수천 개의 정상 행위가 자동 등록됩니다.*

### 2단계: 수동 룰 추가 및 튜닝
필요에 따라 `whitelist.yaml`을 열어 정규표현식(`regex`)을 수동으로 추가할 수 있습니다.
```yaml
# /opt/CAPEv2/modules/processing/whitelist.yaml 예시
network_domains:
  regex:
    - ".*\.windowsupdate\.com"
    - ".*\.mycompany\.internal"
```

### 3단계: 오탐 복원 및 확인
필터링된 정상 데이터가 궁금하다면, 분석 완료 후 `report.json` 최상단의 `noise_filter` 객체를 확인하시면 됩니다.
```json
"noise_filter": {
  "status": "success",
  "filtered_items_count": 5214,
  "filtered_artifacts": {
     "behavior": { "read_keys": [...] },
     "network": { "domains": [...] }
  }
}
```
## Post-Analysis: 필터 통계 확인

샘플 분석이 완료된 후 포함된 `show_stats.py` 도구를 실행하면 Signatures/Reporting으로 전달된 아티팩트(유지된 데이터)의 수와 Windows 백그라운드 노이즈로 안전하게 필터링된 아티팩트의 수를 정확히 확인할 수 있습니다.

```bash
# Usage
python3 show_stats.py /srv/cape/storage/analyses/<TASK_ID>/reports/report.json

# Example
python3 show_stats.py /srv/cape/storage/analyses/12/reports/report.json
```

이 스크립트는 behavior.summary(유지된 데이터)와 noise_filter.filtered_artifacts(필터링된 데이터)를 비교하여, 두 항목의 개수를 정리해 보여줍니다.
