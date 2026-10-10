# wipetrace PoC - 완전삭제 도구 사용 흔적 판별기

Windows 11에서 완전삭제 도구가 **있었는지**, **실행되었는지**, **특정 파일을 실제로 완전삭제한 정황이 있는지**를 Eric Zimmerman's Tools의 CSV 출력으로 판별하는 개념 증명(PoC) 코드입니다.

## 1. 저장소 구성

```
wipetrace-poc/
├── wipetrace.py                  # 판별기 본체
├── signatures.yaml               # 도구별 시그니처와 판별 규칙
├── evaluate.py                   # 판별 결과를 정답표와 대조하는 채점기
├── freeze_manifest.json          # 고정 시각과 세 파일의 SHA-256
└── tests/
    ├── make_synthetic.py         # 테스트용 합성 CSV 생성
    ├── test_wipetrace.py         # 단위 테스트 31개
    ├── answers_synthetic.csv     # 합성 자료의 정답표
    └── results_synthetic.csv     # 합성 자료의 판별 결과
```

## 2. 고정 상태

- 고정 시각: 2026-10-05 15:42:45 UTC
- 버전: `wipetrace.py` 0.5.1, `signatures.yaml` 0.6
- 고정 뒤에는 `wipetrace.py`, `evaluate.py`, `signatures.yaml`을 수정하지 않았습니다. 세 파일의 SHA-256은 `freeze_manifest.json`에도 있습니다.

| 파일 | SHA-256 |
|---|---|
| `wipetrace.py` | b48150b84758960643a000b7705be5fcad0737160e645391687f193b2a630027 |
| `evaluate.py` | 0bdbb6d7b621ac4d0602bb5bddc64d95152d55b924fa9f4abdee1b9d991e4aa3 |
| `signatures.yaml` | 7817bffe981854ab3db22971fc596f48d4ea63c14269c2bc0c980966c3d98b7f |

## 3. 무엇을 판별하나

판별 항목은 네 가지이며 위에서부터 차례로 확인합니다.

| 판별 항목 | 근거 |
|---|---|
| 존재 흔적 | Amcache, 설치(Uninstall)·도구 레지스트리 키, 프로그램 경로 |
| 실행 흔적 | Prefetch(최근 8회 실행 시각), UserAssist, BAM, MUICache. MUICache는 실행 시각이 없어 실행 흔적에만 쓰고 도구 연계에는 쓰지 않음 |
| 완전삭제 의심 패턴 | 변경 저널(`$UsnJrnl:$J`)에서 같은 파일의 삭제 전 `burst_window_sec`(300초) 안에 덮어쓰기(DataOverwrite)와 `min_renames`(1)회 이상의 이름 변경이 함께 기록됨 |
| 도구 연계 | 실행 시각이 삭제 시각 전 `link_window_min`(30분) ~ 후 `link_slack_min`(2분) 안이고, 바뀐 이름이 그 도구의 이름 변경 규칙과 일치 |

판별 방식은 세 가지입니다.

| 판별 방식 | 완전삭제로 보는 조건 |
|---|---|
| 실행 흔적만(`exec`) | 도구 실행 흔적이 있음 |
| 저널만(`journal`) | 저널의 완전삭제 의심 패턴이 있음 |
| 실행 흔적 + 저널(`both`) | 완전삭제 의심 패턴 파일 가운데 도구 연계가 성립한 것이 하나 이상 있음 |

결과 파일의 `stage` 값(0~4)은 위 네 항목 중 어디까지 확인되었는지를 나타내며, 0은 확인된 항목이 없음을 뜻합니다. `alert_exec`, `alert_journal`, `alert_both` 열은 각 판별 방식의 결과이고 1이면 조건을 만족한 것입니다. 필요한 입력이 없으면 빈칸(판단 불가)이며 채점에서 U+·U-로 셉니다.

## 4. 사용법

```
pip install pyyaml
```

Python 3.9 이상이며 다른 외부 라이브러리는 쓰지 않습니다. Python 3.14.3, PyYAML 6.0.3에서 확인했습니다.

### 4.1. 입력 만들기(분석 대상 1건 = 폴더 1개)

분석 대상 디스크를 읽기 전용으로 연결했다고 가정합니다. 아래 예에서 `X:`는 시스템 볼륨, `Y:`는 삭제 여부를 확인할 데이터 볼륨입니다.

```
PECmd.exe -d "X:\Windows\Prefetch" --csv "cases\case01\prefetch"
RECmd.exe --bn BatchExamples\Kroll_Batch.reb -d "X:\" --csv "cases\case01\registry"
AmcacheParser.exe -f "X:\Windows\appcompat\Programs\Amcache.hve" -i --csv "cases\case01\amcache"
MFTECmd.exe -f "Y:\$Extend\$J" -m "Y:\$MFT" --csv "cases\case01\usn"
MFTECmd.exe -f "Y:\$MFT" --csv "cases\case01\mft"
```

폴더 이름에는 조건이나 도구 이름을 넣지 않고, 정답은 `answers.csv`에 따로 둡니다.

### 4.2. 판별과 채점

```
python wipetrace.py analyze cases\case01 --sig signatures.yaml --out reports\case01
python wipetrace.py batch   cases --sig signatures.yaml --out results.csv --reports reports
python evaluate.py results.csv answers.csv --out eval.md
```

`answers.csv`의 열은 `case,scenario,tool,use`입니다. 채점기는 scenario가 `S4`인 실행을 양성으로, 그 밖을 음성으로 봅니다. tool 값은 `signatures.yaml`의 id(`eraser`, `easttec`, `sdelete`, `bleachbit`, `moo0`)와 같게 씁니다.

### 4.3. 테스트

```
python -m unittest tests/test_wipetrace.py -v
```

합성 실행 15개로 31개 검사를 합니다. `tests/`의 자료는 코드가 도는지 확인하려고 만든 합성 CSV이며 실험 결과가 아닙니다.

## 5. 한계

- 변경 저널에는 프로세스 ID가 없으므로 도구 연계는 **정황**입니다. 도구 연계가 성립하지 않았다는 결과는 "삭제하지 않았다"는 뜻이 아닙니다.
- 판별기는 데이터 영역(원래 저장 위치의 내용), Prefetch의 참조 파일 목록, 예약 작업, Compatibility Assistant 기록을 읽지 않습니다.
- 이름 변경 규칙은 도구별 1회 관찰(파일 6개)로 정한 것입니다. 도구 버전이나 설정이 바뀌면 맞지 않을 수 있습니다. 확장자가 없는 파일에서는 Eraser와 Moo0 File Shredder의 규칙이 겹칠 수 있습니다.
- 규칙을 정하고 확인한 자료는 도구별 1회씩이고 가상머신 한 대의 한 가지 환경(Windows 11, NTFS, 네트워크 미연결)에서 수집했습니다. 다른 환경으로 일반화할 수 없습니다.
- Moo0 File Shredder의 실행 파일 이름(`FileShredder.exe`)은 흔한 이름이라 다른 제품과 겹칠 수 있습니다.
- `DataOverwrite`가 있어도 파일 전체가 덮어써졌다는 뜻은 아닙니다. 판별 결과는 완전삭제 의심과 도구 연계 정황까지입니다.
- 설치 파일 이름이 도구 실행 파일과 같으면 설치만 한 경우에도 실행 흔적이 있는 것으로 판별됩니다.
