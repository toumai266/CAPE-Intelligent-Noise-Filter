# CAPE Noise Filter Plugin 운영 문서

## 1. 문서 목적
이 문서는 CAPE v2 환경에서 동작하는 `noise_filter.py` + `whitelist.yaml` + `auto_baseline.py` 조합을 처음 도입하는 사람을 대상으로 한다.  
목표는 다음 3가지다.

1. 왜 이 필터가 필요한지 정확히 이해한다.
2. 설치부터 운영까지 실수 없이 재현한다.
3. 장애/오탐 상황에서 복구할 수 있다.

## 2. 대상 독자
- SOC 분석가
- 침해사고 대응(IR) 엔지니어
- 악성코드 분석가
- CAPE 운영/플랫폼 엔지니어

## 3. 한 문장 요약
`noise_filter`는 CAPE의 Processing 단계에서 노이즈를 먼저 정제해, 시그니처/리포팅/외부 연동으로 넘어가는 데이터를 "운영 가능한 품질"로 만드는 전처리 계층이다.

## 4. 배경: 우리가 겪는 실제 문제

### 4.1 현상
- CAPE 분석 결과(`report.json`)에는 악성 행위 외에도 정상 행위가 대량 섞인다.
- 예: OS 텔레메트리 통신, 기본 서비스 호출, 가상화 환경 기본 이벤트.
- 결과적으로 분석가가 실제 IOC를 찾기 위해 과도한 수동 정리를 수행한다.

### 4.2 운영 영향
- 분석 지연: triage 시간이 늘어나 큐 적체 발생.
- 오탐 증가: 외부 연동 시 불필요 IOC가 유입.
- 유지보수 비용 증가: 시그니처별 하드코딩 예외 관리가 파편화됨.

## 5. "시그니처가 있는데 왜 또 필터가 필요한가?"

### 5.1 맞는 부분
- 많은 시그니처는 자체적으로 부분 whitelist를 갖고 있어 알럿 오탐을 줄인다.

### 5.2 개선이 필요한 부분
- 시그니처는 주로 "알럿 판단"을 담당하며, 원본 데이터 자체를 정제하지 않는다.
- 즉, `behavior`/`network` 데이터는 노이즈를 포함한 채 남는다.

### 5.3 중앙 전처리 필터가 필요한 이유
1. 데이터 품질 보장: 후단(SIEM/MISP/SOAR)에 전달되는 입력 자체가 정제된다.
2. 전역 정책화: 단일 `whitelist.yaml`로 예외 정책을 일관되게 관리한다.
3. 연산 효율: 시그니처 단계에 전달되는 데이터 양을 줄여 처리 비용을 절감한다.

## 6. CAPE 기본 흐름과 개입 지점

### 6.1 기본 흐름(개념)
1. 샘플 실행 (Guest VM)
2. 행위 수집 (monitor/log)
3. Processing 모듈 파싱 (`behavior.py`, `network.py`)
4. Signature 평가
5. Reporting 출력

### 6.2 개입 지점
- `noise_filter.py`는 3번과 4번 사이에 위치한다.
- 권장 순서:
  - `behavior.py`: `order=2`
  - `noise_filter.py`: `order=3`

## 7. 솔루션 아키텍처

### 7.1 구성 파일
- `/opt/CAPEv2/modules/processing/noise_filter.py`
- `/opt/CAPEv2/modules/processing/whitelist.yaml`
- `/opt/CAPEv2/utils/auto_baseline.py`

### 7.2 핵심 원칙
- 파괴적 삭제를 피한다.
- 필터링된 항목은 버리지 않고 격리 저장한다.
- 룰 관리는 코드가 아니라 YAML 중심으로 수행한다.

### 7.3 데이터 처리 방식
- 입력: `self.results` (in-memory results dict)
- 처리: behavior/network 하위 주요 리스트를 규칙 기반 필터링
- 출력:
  - 정제된 원래 위치의 데이터
  - `results["noise_filter"]["filtered_artifacts"]`에 격리된 항목

## 8. 필터링 대상과 데이터 계약

### 8.1 Behavior 영역(예시)
- `read_keys`
- `write_keys`
- `delete_keys`
- `read_files`
- `write_files`
- `delete_files`
- `mutexes`
- `executed_commands`

### 8.2 Network 영역(예시)
- `domains`
- `hosts`
- `http`

### 8.3 결과 데이터 형태(예시)
```json
{
  "behavior": {
    "summary": {
      "executed_commands": ["...정제 후 남은 값..."]
    }
  },
  "network": {
    "domains": [{"domain": "example.com"}]
  },
  "noise_filter": {
    "filtered_artifacts": {
      "executed_commands": ["...필터링된 값..."],
      "domains": [{"domain": "..."}]
    }
  }
}
```

## 9. 룰 엔진 설계

### 9.1 Exact Match
- 고정 문자열 기반 빠른 매칭.
- 장점: 속도/명확성.
- 용도: 변하지 않는 키/경로/도메인.

### 9.2 Regex Match
- 패턴 기반 유연 매칭.
- 장점: 환경별 가변 경로 대응.
- 주의: 과도한 범위 패턴은 과필터링 위험.

### 9.3 딕셔너리 타입 처리
- network 이벤트는 dict 형태가 많다.
- 내부 키(`domain`, `ip`, `uri` 등)에서 매칭 대상 필드를 추출해 룰 적용.

## 10. 사전 준비(Prerequisites)
- CAPE v2 정상 동작 상태
- CAPE processor 재시작 권한
- `cape` 계정으로 파일 권한 부여 가능
- 운영 중단 가능 시간(재시작 포함) 확보
- 기존 `processing.conf`, `whitelist.yaml` 백업

## 11. 설치 절차

### 11.1 파일 배치
```bash
sudo cp noise_filter.py whitelist.yaml /opt/CAPEv2/modules/processing/
sudo cp auto_baseline.py /opt/CAPEv2/utils/
# 선택: 분석 후 통계 요약 도구
sudo cp show_stats.py /opt/CAPEv2/utils/
```

### 11.2 권한 설정
```bash
sudo chown cape:cape \
  /opt/CAPEv2/modules/processing/noise_filter.py \
  /opt/CAPEv2/modules/processing/whitelist.yaml \
  /opt/CAPEv2/utils/auto_baseline.py \
  /opt/CAPEv2/utils/show_stats.py

sudo chmod +x /opt/CAPEv2/utils/auto_baseline.py
sudo chmod +x /opt/CAPEv2/utils/show_stats.py
```

### 11.3 설정 활성화
```bash
echo -e "\n[noise_filter]\nenabled = yes\n" | sudo tee -a /opt/CAPEv2/conf/processing.conf
```

### 11.4 서비스 재시작
```bash
sudo systemctl restart cape-processor.service
```

### 11.5 설치 후 즉시 확인
```bash
grep -n "\[noise_filter\]" /opt/CAPEv2/conf/processing.conf
ls -l /opt/CAPEv2/modules/processing/noise_filter.py
ls -l /opt/CAPEv2/modules/processing/whitelist.yaml
ls -l /opt/CAPEv2/utils/auto_baseline.py
ls -l /opt/CAPEv2/utils/show_stats.py
```

## 12. 운영: 기본 베이스라인 설정

### 12.1 도입
- 회사/이미지마다 정상 행위가 다르다. 
- 기본 룰만으로 운영하면 과소필터링 또는 과필터링이 발생한다.

### 12.2 권장 순서
1. 기본 베이스라인 Task
2. 인터랙션 베이스라인 Task
3. 업무앱 베이스라인 Task(HWP/PDF/브라우저 등)

### 12.3 학습 명령
```bash
sudo -u cape python3 /opt/CAPEv2/utils/auto_baseline.py <TASK_ID>
```

### 12.4 학습 직후 확인 항목
- `whitelist.yaml` 변경 여부
- 필터 적용 후 리포트의 노이즈 감소 여부
- `filtered_artifacts`가 정상 기록되는지

## 13. 운영 Runbook(반복 운영) 제안

### 13.1 주기
- 주 1회 정기 점검 + 신규 이미지 배포 시 추가 점검.

### 13.2 변경 관리
1. 룰 수정 전 백업
2. 변경 사유 기록(티켓/커밋 메시지)
3. 샘플 재분석으로 영향 확인
4. 문제가 없으면 운영 반영

### 13.3 추천 운영 원칙
- regex는 최소 범위로 작성
- exact 우선, regex 후순위
- 의심 항목은 즉시 삭제하지 말고 격리 데이터로 검토

## 14. 검증 방법(Before/After)

### 14.1 기능 검증
- 동일 샘플을 필터 ON/OFF로 각각 실행
- 다음 지표 비교:
  - behavior 항목 수
  - network 항목 수
  - analyst 수동 분류 시간
  - 후단 파이프라인 오탐 건수

### 14.2 품질 검증 기준 예시
- 정제 이후에도 핵심 악성 행위가 유지되어야 함
- 노이즈만 줄고, 탐지해야 할 행위가 사라지면 실패

### 14.3 `show_stats.py` 기반 요약 검증(권장)
`show_stats.py`는 분석 종료 후 `report.json` 하나만으로 필터 전/후 아티팩트 규모를 빠르게 비교하는 점검 도구다.

```bash
python3 /opt/CAPEv2/utils/show_stats.py /srv/cape/storage/analyses/<TASK_ID>/reports/report.json
```

핵심 확인 값:
- `Total API/Artifacts BEFORE Filtering`
- `Noise Artifacts FILTERED OUT`
- `Total Artifacts AFTER Filtering`

현재 스크립트의 계산 기준:
- `AFTER`: `behavior.summary` 하위 리스트 총합
- `FILTERED`: `noise_filter.filtered_artifacts.behavior` 하위 리스트 총합
- `BEFORE = AFTER + FILTERED`

스크립트가 기본 비교해 주는 항목:
- `write_files`: 유지된 항목 vs 필터링된 항목
- `read_keys`: 유지된 항목 vs 필터링된 항목
- `mutexes`: 유지된 항목 vs 필터링된 항목

운영 적용 팁:
- 룰 변경 직후 동일 샘플로 `show_stats.py`를 다시 실행해 변경 전/후를 비교한다.
- `FILTERED OUT`만 급증하고 핵심 악성 행위가 사라지면 regex 범위를 축소하고 재검증한다.

## 15. 장애 대응 가이드

### 증상 1: 리포트가 비정상적으로 비어 있음
- 원인 후보: regex 과매칭, 룰 오학습
- 조치:
  1. 최근 룰 변경 롤백
  2. `filtered_artifacts`에서 과필터링 항목 확인
  3. 문제 regex 축소/삭제

### 증상 2: 필터가 적용되지 않음
- 원인 후보: 설정 비활성, 모듈 로드 실패, 권한 문제
- 조치:
  1. `processing.conf`의 `[noise_filter] enabled = yes` 확인
  2. 파일 권한/소유자 확인
  3. processor 로그에서 import/실행 오류 확인

### 증상 3: auto_baseline 실행 실패
- 원인 후보: Task ID 오류, report 경로 접근 문제
- 조치:
  1. Task 존재 여부 확인
  2. `cape` 계정으로 실행했는지 확인
  3. 관련 파일 권한 확인

## 16. 보안 및 거버넌스
- `whitelist.yaml`은 탐지 정확도에 직접 영향을 주므로 변경 권한을 제한한다.
- 룰 변경 시 2인 리뷰 권장.
- 운영 반영 전 샘플 검증 결과를 남긴다.
- 백업 정책:
  - 일 단위 또는 변경 단위 백업
  - 최소 최근 7개 버전 유지

## 17. 성능 관점
- 전처리에서 노이즈를 줄이면 signature 단계 순회량이 감소한다.
- 대량 분석 환경에서 CPU/처리 시간 절감 효과가 크다.
- 단, regex 남용 시 전처리 자체의 비용이 커질 수 있으므로 룰 최적화가 필요하다.

## 18. 적용 범위/호환성
- 하이퍼바이저 독립적(KVM/VMware/VirtualBox 등)
- CAPE Processing 결과 dict 기반 처리이므로 환경 종속성이 낮다.
- CAPE v2 동작 리눅스 서버에서 사용 권장.
- 윈도우 Guest VM 내부 설치는 필요 없다.

## 19. 알려진 한계
- 완전 자동 튜닝은 불가능하며 운영 맥락 기반 룰 관리가 필요하다.
- 회사별 소프트웨어 스택이 다르면 초기 학습 품질 차이가 크다.
- 과도한 whitelist는 탐지 누락을 만들 수 있다.

## 20. 롤백 절차
1. `/opt/CAPEv2/conf/processing.conf`에서 `[noise_filter]` 비활성
2. processor 재시작
3. 기존 백업된 `whitelist.yaml` 복원
4. 동일 샘플 재분석으로 정상 복구 확인

## 21. 빠른 체크리스트
- [ ] 파일 3종 배치 완료
- [ ] 권한/소유자 설정 완료
- [ ] `processing.conf` 활성화 완료
- [ ] processor 재시작 완료
- [ ] Day 1 클린 베이스라인 학습 완료
- [ ] Before/After 검증 완료
- [ ] 롤백 절차 문서화 완료