# 탐지 모듈 판정 기준 (detection_spec)

탐지 모듈(`detector/`)의 판정 기준은 이 문서 하나다. 코드와 테스트(`tests/detector/`)는 이 문서를 따른다.

## 1. 범위

- 대상: 학생이 올린 Flask `.py` 파일 한 개. 코드는 실행하지 않고 구문 트리(AST)만 읽는다.
- 다루는 취약점은 서버 측 10종, 규칙은 30개다.

| 순서 | vuln_id | 이름 | 규칙 |
|---|---|---|---|
| 1 | `sql_injection` | SQL 삽입 | SQL-1 ~ SQL-3 |
| 2 | `os_command_injection` | 운영체제 명령어 삽입 | CMD-1, CMD-2 |
| 3 | `file_upload` | 위험한 형식 파일 업로드 | UP-1, UP-2 |
| 4 | `path_traversal` | 경로 조작 | PATH-1 |
| 5 | `idor` | 부적절한 인가 / IDOR | IDOR-1 ~ IDOR-4 |
| 6 | `ssrf` | 서버사이드 요청 위조 | SSRF-1 |
| 7 | `debug_error_exposure` | 디버그 모드·오류 정보 노출 | DBG-1, DBG-2, ERR-1, ERR-2 |
| 8 | `hardcoded_secret` | 하드코딩된 시크릿 | KEY-1 ~ KEY-4 |
| 9 | `password_storage` | 평문·약한 해시 비밀번호 저장 | PW-1 ~ PW-5 |
| 10 | `login_attempt_limit` | 로그인 보안: 반복된 인증시도 제한 | LOGIN-1 ~ LOGIN-4 |

## 2. 근거 문서와 우선순위

1. **Python 가이드**: 「Python 시큐어코딩 가이드」(2023년 개정본). 항목 정의, 안전한 코딩기법, 예제 코드.
2. **진단가이드**: 「소프트웨어 보안약점 진단가이드」(2021). 진단방법, 설계단계 보안설계 기준.
3. **OWASP·공식 문서**: 위 두 문서에 없는 내용에만 쓴다. 쓴 곳마다 출처를 적는다 (부록 C).

쪽수는 인쇄된 쪽 번호다. 가이드의 문장으로 정할 수 없어 해석이 들어간 곳은 "해석"이라고 적었다.

## 3. 공통 기준

### 3.1 외부 입력값 (출발점)

- `flask.request`에서 꺼낸 값: `args`, `form`, `values`, `json`, `get_json()`, `data`, `get_data()`, `files`, `cookies`, `headers`, `view_args`, `url`, `full_path`, `query_string`
- 라우트 함수가 받는 URL 변수 (`/post/<name>`의 `name`)
- 올린 파일의 `filename`, `content_type`, `mimetype`, `read()`
- 위 값을 담은 변수, 그것으로 만든 문자열(`+`, `%`, f-string, `.format()`), 그것을 넘겨받은 같은 파일의 함수 매개변수
- 다른 파일·라이브러리의 함수에 넘긴 값은 그 결과에도 외부 입력값 표시가 남는다. 함수 안을 볼 수 없기 때문이다.
- dict는 키별로 따로 본다. `{"title": 제목, "password": 비밀번호}`에서 꺼낸 `["title"]`은 비밀번호가 아니다.

### 3.2 검증으로 인정하는 것

검사는 **실패했을 때 중단(return, abort, raise, continue)하는 분기**이거나, 통과한 분기 안에서만 값을 쓰는 경우만 인정한다.

| 검증 | 인정하는 형태 | 적용 | 근거 |
|---|---|---|---|
| V1 화이트리스트 | 상수 목록(list·tuple·set·dict 리터럴, 그것을 담은 상수 변수)에 대한 `in` / `not in`, 상수와의 `==` / `!=`, 상수 dict에서 꺼낸 값, `"A" if … else "B"`처럼 상수 가운데 고른 값 | 전부 | Python 가이드 p.30, p.21, p.57의 안전한 예제. 진단가이드 p.227 "정해진 후보군에서 선택된 값(White List)" |
| V2 숫자 변환 | `int()`, `float()`, URL 변환기 `<int:…>` `<float:…>`, `request.args.get(…, type=int)` | CMD, PATH | 진단가이드 p.227 "적절하게 검증하면 안전" (해석) |
| V3 형식 검사 | `isdigit()` `isdecimal()` `isnumeric()` `isalnum()` `isalpha()`, 영문·숫자·`_`·`-`만 허용하는 문자 클래스로 된 `re.fullmatch` | CMD, PATH | 위와 같음 (해석) |
| V4 문자 제거 | `.replace(문자, "")`, `re.sub("[…]", "", 값)`로 아래 문자를 **모두** 지운 값 | CMD, PATH | CMD: Python 가이드 p.29, p.32의 `\| ; & : > < \` \\ !` 아홉 문자. PATH: Python 가이드 p.18~19의 `/`, `\`, `.` |
| V5 전용 함수 | `shlex.quote()` | CMD | Python 가이드 p.31 |
| | `werkzeug.utils.secure_filename()`, `werkzeug.security.safe_join()`, `flask.send_from_directory()` | PATH | Werkzeug·Flask 문서 (부록 C-4, C-5) |

- **SQL에는 V1만 인정한다.** Python 가이드 p.9~11이 제시하는 방법은 바인딩이다. 숫자로 바꾼 값이나 따옴표를 지운 값도 문장에 이어 붙이면 걸린다.
- **SSRF에는 V1만 인정한다.** Python 가이드 p.57이 제시하는 방법은 화이트리스트다.
- 검사한 값과 쓰는 값이 다르면 인정하지 않는다. 확장자만 검사하고 원래 파일명 전체를 쓰는 경우가 그 예다 (Python 가이드 p.19의 안전하지 않은 예제).
- 인정하지 않는 것: 블랙리스트, `startswith`, `"글자" in 값`, 정규식의 부분 일치(`re.search`), `os.path.basename()`, 직접 만든 검사 함수.
- 같은 파일의 함수가 V1·V3 검사의 결과를 그대로 돌려주면 그 검사로 인정한다 (예: `allowed_file()`).

### 3.3 같은 파일의 함수 따라가기

- 같은 파일에 정의된 함수와, 같은 파일에 정의된 클래스의 메서드를 호출하면 인자의 상태를 가지고 그 안을 따라간다 (최대 4단계).
- 같은 파일의 데코레이터가 원래 함수를 부르기 전에 한 검사는 그 라우트의 검사로 본다. `flask_login.login_required`는 로그인 확인으로 본다.
- 어디서도 호출되지 않는 함수는 매개변수를 "알 수 없는 값"으로 두고 따로 본다. 이때 비밀번호 이름의 매개변수는 비밀번호 값으로 본다 (메서드는 제외).

### 3.4 보고하는 줄

- 줄 단위로 보고한다 (1부터). 같은 줄의 같은 규칙은 한 번만 보고한다.
- 흐름을 따라가는 규칙(SQL, CMD, PATH, SSRF, PW)은 **값을 마지막으로 이어 붙이거나 묶은 함수가 도착점까지 넘긴 줄**을 보고한다.
  - 라우트에서 SQL 문장을 만들어 도우미 함수에 넘겼다면: 도우미를 부른 줄.
  - 도우미 함수 안에서 문장을 이어 붙였다면: 그 도우미 안의 실행 줄.
- `path`에는 출발점부터 그 줄까지 거친 줄을 순서대로 넣는다. 흐름을 따라가지 않는 규칙은 그 줄 하나만 넣는다.
- 그 밖의 규칙이 보고하는 줄은 각 항목에 적었다.

### 3.5 판정

- 규칙에 하나라도 걸리면 그 취약점은 "위험", 아니면 "안전"이다.
- "안전"은 이 문서의 규칙에 걸리지 않았다는 뜻이다.
- 학생에게 물어야 판정할 수 있는 항목은 판정 전에 질문을 돌려준다 (5장).

## 4. 항목별 기준

### 4.1 SQL 삽입 (`sql_injection`)

근거: Python 가이드 p.8~13 (입력데이터 검증 및 표현 1), 진단가이드 p.180~186, p.506 (SR1-1).

| 규칙 | 위험으로 보는 것 |
|---|---|
| SQL-1 | 외부 입력값이 문자열 결합·포맷으로 SQL 문장에 들어간 채 실행된다 |
| SQL-2 | 외부 입력값이 `ORDER BY` 뒤(정렬 기준 자리)에 들어간다 |
| SQL-3 | 외부 입력값이 아니어도, 고정이 아닌 값(DB에서 읽은 값, 세션 값 등)을 SQL 문장에 이어 붙인다 |

- 도착점: `execute()`, `executemany()`, `executescript()`, `.raw()`의 SQL 문장 인자, `sqlalchemy.text()`의 인자.
- 안전: 문장은 고정하고 값을 두 번째 인자로 바인딩한다. Python 가이드 p.11 "정적인 쿼리문을 사전에 생성하고 사용자 입력을 바인딩".
- SQL-2는 바인딩할 수 없는 자리이므로 V1(화이트리스트)로 고친다. 진단가이드 p.506 SR1-1 ③ "동적으로 SQL쿼리문을 생성해야 하는 경우, 입력값에 대한 검증을 수행한 뒤 사용".
- 코드에 적힌 상수나 상수 가운데 고른 값으로 문장을 이어 붙이는 것은 걸리지 않는다 (`f"SELECT … {where}"`에서 `where`가 고정 문자열 둘 중 하나인 경우, `",".join("?" * n)`).
- SQL-3은 고정 글자와 알 수 없는 값을 **이어 붙인** 경우만 본다. 문장 전체가 알 수 없는 값(매개변수로 받은 문장을 그대로 실행)이면 걸리지 않는다.

### 4.2 운영체제 명령어 삽입 (`os_command_injection`)

근거: Python 가이드 p.29~32 (입력데이터 검증 및 표현 5), 진단가이드 p.223~227.

| 규칙 | 위험으로 보는 것 |
|---|---|
| CMD-1 | 외부 입력값이 검증 없이 운영체제 명령어의 일부 또는 전부로 실행된다 |
| CMD-2 | 특수문자를 지운 외부 입력값이 들어간 명령어를 `shell=True`로 실행한다 |

- 도착점: `os.system()`, `os.popen()`, `subprocess.run()` `call()` `check_call()` `check_output()` `Popen()` `getoutput()` `getstatusoutput()`의 명령어 인자 (문자열, 또는 리스트의 원소).
- 안전:
  - 허용 목록에 있는 값만 실행한다 (V1). Python 가이드 p.30.
  - 특수문자 아홉 개를 모두 지우고(V4) 또는 `shlex.quote()`를 거쳐(V5), `shell=True` 없이 실행한다. Python 가이드 p.31~32.
  - 숫자 변환·형식 검사(V2·V3)를 거친 값.
- CMD-2: Python 가이드 p.31 "shell의 옵션은 삭제해야 한다". V4·V5만 거친 값이 `shell=True` 호출에 들어간 경우다.
- 검증하지 않은 값은 `shell=True` 여부와 관계없이 CMD-1 하나만 보고한다.

### 4.3 위험한 형식 파일 업로드 (`file_upload`)

근거: Python 가이드 p.33~35 (입력데이터 검증 및 표현 6), 진단가이드 p.232~235.

올린 파일(`request.files`에서 꺼낸 것)을 `.save()`로 저장하는 줄마다 본다. 보고하는 줄은 저장하는 줄이다.

| 규칙 | 위험으로 보는 것 | 근거 |
|---|---|---|
| UP-1 | 저장 전에 확장자를 허용 목록으로 확인하지 않는다 | Python 가이드 p.33, 진단가이드 p.235 |
| UP-2 | 저장 전에 Content-Type을 허용 목록으로 확인하지 않는다 | Python 가이드 p.33 "확장자 및 … Content-Type도 함께 확인" |

- UP-1 안전: 그 파일의 이름에서 확장자를 떼어(`rsplit(".", 1)[-1]`, `split(".")[-1]`, `os.path.splitext(…)[1]`) 상수 목록과 비교하거나, `endswith(상수)`로 확인하고 실패 시 중단한다. Flask 문서의 `allowed_file()` 형태를 포함한다 (부록 C-5).
- UP-2 안전: 그 파일의 `content_type` 또는 `mimetype`을 상수 목록·상수와 비교하고 실패 시 중단한다.
- 인정하지 않는 것: `"jpg" in filename`, `mimetype.startswith("image/")`.
- 여러 파일을 반복해 저장하면 파일마다 확인해야 한다.
- 저장 경로에 올린 파일의 이름을 그대로 쓰는 문제는 4.4(PATH-1)에서 본다.

### 4.4 경로 조작 (`path_traversal`)

근거: Python 가이드 p.18~21 (입력데이터 검증 및 표현 3), 진단가이드 p.201~206. 가이드 항목의 "자원 삽입"(소켓 포트 등)은 이 항목의 범위가 아니다.

| 규칙 | 위험으로 보는 것 |
|---|---|
| PATH-1 | 외부 입력값이 검증 없이 파일 경로에 들어간다 |

- 도착점: `open()`, `os.remove()` `unlink()` `rmdir()` `listdir()` `mkdir()` `makedirs()` `rename()` `replace()` `scandir()`, `shutil.rmtree()` `copy()` `copy2()` `copyfile()` `move()`, `flask.send_file()`, 올린 파일의 `.save()` 경로 인자, `pathlib.Path(…)`로 만든 경로의 `open()` `read_text()` `read_bytes()` `write_text()` `write_bytes()` `unlink()` 등.
- 올린 파일의 이름(`.filename`)도 외부 입력값이다. Flask 문서는 저장 전에 항상 `secure_filename()`을 쓰라고 한다 (부록 C-5).
- 안전: V1, V2, V3, V4(`/`, `\`, `.` 세 문자를 모두 제거), V5(`secure_filename`, `safe_join`, `send_from_directory`).
- 확장자만 검사한 것, `..`만 지운 것, `os.path.basename()`은 안전이 아니다.

### 4.5 부적절한 인가 / IDOR (`idor`)

근거: Python 가이드 p.72~74 (보안기능 2 부적절한 인가), p.69~71 (보안기능 1), p.64 (보안기능 결정에 사용되는 부적절한 입력값), 진단가이드 p.317, p.322. "IDOR"라는 용어와 객체 단위 확인은 가이드에 없어 OWASP를 따른다 (부록 C-1).

**후보 라우트**: URL 변수나 id류 요청값으로 DB의 대상을 골라 조회·수정·삭제하는 라우트 함수.

- 고르는 자리: `execute()`의 문장·바인딩 값, ORM의 `get` `filter_by` `filter` `where` `get_or_404` `first_or_404` 인자. `INSERT` 문장은 이미 있는 대상을 고르지 않으므로 제외한다.
- id류 요청값: 키 이름을 단어로 나눴을 때 `id` `uid` `idx` `no` `num` `seq` `pk` `userid`가 있는 것 (`page`가 든 키는 제외). `username` `email` 키도 해당하지만, 같은 함수가 비밀번호를 읽으면(로그인·가입) 제외한다.
- 조회 조건에 세션 사용자가 함께 들어가면(`WHERE id = ? AND user_id = ?`에 `session["user_id"]`) 그 조회는 보호된 것이다.

**그 라우트에서 확인한 것**에 따라 나눈다. 도우미 함수와 데코레이터에서 한 확인도 포함한다.

| 확인한 것 | 결과 |
|---|---|
| 본인 확인: 세션 사용자(`session[…]`, `current_user`, `g.user`)와 대상의 소유자 필드 또는 요청한 번호를 비교 | 안전 |
| 관리자 확인: 세션의 역할 값이 관리자(`"admin"` `"administrator"` `"관리자"`)인지, 세션의 관리자 표시(`is_admin` 등)가 참인지 확인 | 안전 |
| 대상에 걸린 비밀번호 확인: DB에서 읽은 값과 요청의 비밀번호를 `check_password_hash()` 등으로 대조 | 안전 |
| 아무 확인도 없음 | IDOR-1 |
| 로그인했는지만 확인 | IDOR-2 |
| 요청값처럼 사용자가 바꿀 수 있는 값으로 본인 여부를 판단, 또는 세션 값을 소유자 필드가 아닌 필드와 비교 | IDOR-3 |
| 관리자가 아닌 역할(회원 등)인지만 확인 | IDOR-4 |

- 보고하는 줄: 그 라우트에서 보호되지 않은 첫 조회 줄. 라우트마다 하나만 보고한다.
- 소유자 필드: 이름에 `user` `owner` `author` `writer` `member` `uid` `userid` `username`이 있는 필드. `row[0]`처럼 이름을 알 수 없으면 소유자 필드로 본다.
- IDOR-1: Python 가이드 p.73의 안전하지 않은 예제(권한 확인 없이 삭제). 진단가이드 p.317은 "게시글 수정, 삭제"를 인증이 필요한 기능의 예로 든다.
- IDOR-2: OWASP는 사용자가 접근하려는 객체마다 접근 권한을 확인하라고 한다. Python 가이드 p.73의 안전한 예제도 로그인 확인에 권한 확인을 더한다.
- IDOR-3: Python 가이드 p.64. OWASP는 현재 사용자를 세션 정보로 판단하라고 한다.
- **해석**: "대상에 걸린 비밀번호 확인"을 안전으로 본 것. Python 가이드 p.69는 중요 기능에 재인증을 적용하라고 하고, p.71의 안전한 예제는 저장된 비밀번호와 대조한 뒤에만 수정한다. 글마다 비밀번호를 두는 게시판이 여기에 해당한다.
- 후보에 보호가 없더라도 그 페이지가 공개 정보인지는 코드로 알 수 없다. 진단가이드 p.317도 "진단원이 직접 코드를 보며 해당 정보가 중요정보인지 파악해야" 한다고 한다. 그래서 먼저 학생에게 묻는다 (5.1).

### 4.6 서버사이드 요청 위조 (`ssrf`)

근거: Python 가이드 p.55~57 (입력데이터 검증 및 표현 12), 진단가이드 p.276~278.

| 규칙 | 위험으로 보는 것 |
|---|---|
| SSRF-1 | 외부 입력값으로 정한 주소로 서버가 요청을 보낸다 |

- 도착점: `requests`·`httpx`의 `get` `post` `put` `patch` `delete` `head` `options` `request`, `requests.Session`·`httpx.Client` 객체의 같은 메서드, `urllib.request.urlopen()`, `urllib.request.Request()`의 주소 인자.
- 안전: 허용 목록으로 검증한 주소, 상수 dict에서 꺼낸 주소 (V1). Python 가이드 p.57.
- **해석**: 주소가 코드에 적힌 `scheme://호스트/`로 시작하고 외부 입력값이 그 뒤(경로·쿼리)에만 붙으면 걸리지 않는다. 요청이 가는 서버를 외부 입력값이 정하지 못하기 때문이다.
- 인정하지 않는 것: 도메인 포함 여부 비교, `startswith`, 블랙리스트.
- 위험일 때 학생에게 "꼭 필요한 기능인지" 묻고 확인 표시만 한다 (5.2). 판정은 바뀌지 않는다.

### 4.7 디버그 모드·오류 정보 노출 (`debug_error_exposure`)

근거: Python 가이드 p.146~149 (캡슐화 2 제거되지 않고 남은 디버그 코드), p.125~128 (에러처리 1 오류 메시지 정보노출), 진단가이드 p.479, p.421. Flask 문서 (부록 C-6).

| 규칙 | 위험으로 보는 것 | 보고하는 줄 |
|---|---|---|
| DBG-1 | 디버그 모드를 켠다 | debug 값이 적힌 줄 |
| DBG-2 | 디버그 값이 상수가 아니어서 꺼져 있는지 코드로 확인할 수 없다 (환경변수 등) | debug 값이 적힌 줄 |
| ERR-1 | 예외 내용을 응답으로 내보낸다 | 그 `return` 줄 |
| ERR-2 | 오류 추적 정보를 출력한다 | 그 호출 줄 |

- 디버그 값을 정하는 자리: `app.run(debug=…)`(세 번째 위치 인자 포함), `app.debug = …`, `app.config["DEBUG"] = …`, `app.config.update(DEBUG=…)`, `app.config.from_mapping(DEBUG=…)`.
- `True`이면 DBG-1, `False`이면 안전, 상수를 담은 변수는 그 값으로 본다. 그 밖에는 DBG-2다. Python 가이드 p.146 "app.run() 전에 debug = False로 설정". `debug` 인자가 없으면 안전이다.
- ERR-1: `return`하는 값에 예외 객체가 들어 있다 (`str(e)`, `repr(e)`, f-string, `e.args`, `jsonify(error=str(e))`, 템플릿에 넘기는 인자). `traceback.format_exc()`도 같다. Python 가이드 p.125 "예외 이름이나 추적 메시지".
  - 예외 객체는 `except … as e`의 `e`와 `@app.errorhandler` 함수의 첫 매개변수다.
  - 예외 객체의 `code`, `name`, `description` 속성만 쓰는 것은 걸리지 않는다. HTTP 오류에 미리 정해진 값이다.
  - 로그에 남기는 것(`app.logger.error(e)`)은 걸리지 않는다. Python 가이드 p.128의 안전한 예제.
- ERR-2: `traceback.print_exc()`, `traceback.print_exception()`, `print(traceback.format_exc())`. Python 가이드 p.127.

### 4.8 하드코딩된 시크릿 (`hardcoded_secret`)

근거: Python 가이드 p.85~87 (보안기능 6 하드코드된 중요정보), p.109~110 (보안기능 13 주석문 안에 포함된 시스템 주요정보), 진단가이드 p.357, p.388. 이 항목은 흐름을 따라가지 않고 코드의 모양만 본다.

| 규칙 | 위험으로 보는 것 |
|---|---|
| KEY-1 | Flask 세션 서명 키를 코드에 적었다: `….secret_key = "…"`, `….config["SECRET_KEY"] = "…"`, `….config.update(SECRET_KEY="…")` |
| KEY-2 | 비밀번호·키를 코드에 적었다: 비밀 이름의 변수·속성·dict 키·키워드 인자에 리터럴을 넣거나, 비밀 이름의 값을 리터럴과 `==` `!=`로 비교 |
| KEY-3 | 환경변수가 없을 때 쓰는 기본값에 비밀 값을 적었다: `os.getenv("이름", "값")`, `os.environ.get("이름", "값")` |
| KEY-4 | 주석에 비밀번호·키가 적혀 있다 |

- 보고하는 줄: 그 값(리터럴)이 적힌 줄. KEY-3은 기본값이 적힌 줄, KEY-4는 그 주석 줄.
- 비밀 이름: 이름을 단어로 나눴을 때(`_`, 대소문자 경계) `password` `passwd` `pwd` `pw` `secret` `token` `apikey`가 있는 것. `key`는 이름 전체가 `key`이거나 `api` `secret` `private` `access` `auth` `encryption` `signing` 등의 수식어 바로 뒤에 올 때만 해당한다. `sort_key`, `cache_key`는 해당하지 않는다.
- 리터럴: 비어 있지 않은 문자열·bytes 리터럴, 또는 그것들만 이어 붙인 값(리터럴만 대입된 변수 포함). 빈 문자열과 숫자는 걸리지 않는다.
- KEY-3: 비밀 이름의 자리에 넣는 값이거나, 환경변수 이름이 비밀 이름일 때 본다.
- KEY-2의 비교: 진단가이드 p.357 "사용자·관리자 비밀번호가 소스코드 안에 직접 코딩되어 있는지". 비교에서는 이름이 `key` 한 단어인 것을 뺀다.
- KEY-4: 주석(`#`)에서 비밀 이름 또는 `비밀번호`·`패스워드`·`암호` 뒤에 `=`나 `:`가 오고 그 뒤에 값이 있는 경우. Python 가이드 p.109의 예제(`# passwd = passw0rd`).
  - 따옴표로 감싼 값은 해당한다.
  - 따옴표가 없는 값은 숫자나 기호가 섞여 있을 때만 해당한다 (`admin1234`, `tok-0000`).
  - 값이 한글이면(설명 문장), 괄호·대괄호가 있거나 `a.b` 꼴이면(코드) 해당하지 않는다.
  - 문서화 문자열(docstring)은 보지 않는다.
- 가린 값(`"***"`)도 리터럴이다. 수정 피드백의 가리기(`fixer/masking.py`)가 이 규칙의 `secret_values()`와 `literal_nodes()`로 가릴 자리를 찾는다.

### 4.9 평문·약한 해시 비밀번호 저장 (`password_storage`)

근거: Python 가이드 p.81~84 (보안기능 5 암호화되지 않은 중요정보), p.77~80 (보안기능 4 취약한 암호화 알고리즘 사용), p.111~112 (보안기능 14 솔트 없이 일방향 해시 함수 사용), 진단가이드 p.334, p.346, p.393. 가이드에 없는 해시 방식은 OWASP·Werkzeug 문서 (부록 C-2, C-4).

**비밀번호 값**: 요청에서 비밀번호 이름의 키로 꺼낸 값, 어디서도 호출되지 않는 함수의 비밀번호 이름 매개변수. 비밀번호 이름은 단어로 나눴을 때 `password` `passwd` `pwd` `pw`가 있거나 `비밀번호` `패스워드` `암호`가 들어 있는 이름이다.

**저장 자리**:

- `INSERT`·`UPDATE`·`REPLACE`로 시작하는 문장을 실행하는 `execute()` `executemany()`의 문장과 바인딩 값
- 비밀번호 이름의 속성에 대입 (`user.password = …`)
- 같은 파일에 정의된 클래스를 만들 때의 비밀번호 이름 키워드 인자 (`User(password=…)`)
- 모듈 최상위에 두고 내용을 바꿔 쓰는 dict·list에 넣는 값 (`users[name] = {"password": …}`)

비밀번호 값이 저장 자리에 도착할 때까지 거친 처리에 따라 판정한다.

| 규칙 | 위험으로 보는 것 | 근거 |
|---|---|---|
| PW-1 | 해시하지 않고 그대로 저장한다 | Python 가이드 p.82 |
| PW-2 | MD5, SHA-1, MD4로 해시한다 (솔트가 있어도) | Python 가이드 p.77, p.80, 진단가이드 p.334 |
| PW-3 | SHA-2·SHA-3 계열로 해시하면서 솔트를 넣지 않는다 | Python 가이드 p.111 |
| PW-4 | 솔트가 코드에 적힌 고정 값이거나 `random` 모듈로 만든 값이다 | Python 가이드 p.111 "사용자별로 유일하게", "os.urandom() 등 안전한 난수" |
| PW-5 | 이 프로그램이 확인할 수 없는 방식으로 처리한다: 아래 목록에 없는 해시(`blake2b` 등), `passlib`, 다른 파일의 함수 | Python 가이드 p.77 "검증된 표준화된 알고리즘을 사용" |

- 안전:
  - `hashlib`의 `sha224` `sha256` `sha384` `sha512` `sha3_*`, `Crypto.Hash`의 같은 방식에 솔트를 함께 넣는다 (Python 가이드 p.82, p.112).
  - `hashlib.pbkdf2_hmac()`(해시 이름이 위 목록에 있을 때), `hashlib.scrypt()`에 솔트를 넣는다.
  - `werkzeug.security.generate_password_hash()`. scrypt(기본) 또는 pbkdf2를 쓰고 솔트를 스스로 만든다 (부록 C-4).
  - `bcrypt.hashpw(값, bcrypt.gensalt())`, `argon2.PasswordHasher().hash()`, `flask_bcrypt`의 `generate_password_hash()`. OWASP가 권장하는 방식이다 (부록 C-2).
- 솔트:
  - 안전한 솔트: `os.urandom()`, `secrets.token_bytes()` `token_hex()` `token_urlsafe()`로 만든 값, DB에서 읽어 온 값(그 사용자의 저장된 솔트), `bcrypt.gensalt()`.
  - PW-4: 문자열 리터럴(상수 변수 포함), `random` 모듈의 값.
  - 매개변수로 받은 값처럼 어디서 왔는지 알 수 없는 솔트는 판정하지 않는다. Python 가이드 p.82의 안전한 예제가 솔트를 매개변수로 받는다.
- 우선순위: PDF가 기준이므로 솔트를 넣은 SHA-256은 안전으로 본다. OWASP는 SHA-256 같은 빠른 해시가 비밀번호 저장에 맞지 않다고 하지만, 가이드에 있는 내용은 가이드를 따른다.
- `strip()`, `encode()`, `str()`처럼 내용을 바꾸지 않는 처리는 처리로 치지 않는다.
- `SELECT` 문장에 비밀번호를 넣는 것은 저장이 아니다.

### 4.10 로그인 보안: 반복된 인증시도 제한 (`login_attempt_limit`)

근거: Python 가이드 p.116~118 (보안기능 16 반복된 인증시도 제한 기능 부재), 진단가이드 p.404, p.110~111 (설계 2.2 인증 수행 제한), p.563. OWASP (부록 C-3).

**인증 지점**: 요청에서 받은 비밀번호를 확인하는 라우트 함수. `check_password_hash()`, `bcrypt.checkpw()`, `argon2`·`passlib`의 `verify()`를 부르거나, 비밀번호 값(또는 그 해시)을 `==` `!=`로 저장된 값과 비교하는 곳이다. 같은 파일의 도우미 함수 안에서 확인하는 것도 포함한다. 로그인뿐 아니라 글 비밀번호 확인도 인증 시도다. 요청의 값 둘을 서로 비교하는 것(비밀번호 재입력 확인)은 해당하지 않는다.

| 규칙 | 위험으로 보는 것 | 보고하는 줄 | 근거 |
|---|---|---|---|
| LOGIN-1 | 인증 실패 횟수를 제한하지 않는다 | 그 함수의 `def` 줄 | Python 가이드 p.117의 안전하지 않은 예제 |
| LOGIN-2 | 허용하는 실패 횟수가 5번을 넘거나 코드로 확인할 수 없다 | 횟수를 비교하는 줄 | 진단가이드 p.110 "로그인 시도횟수를 3~5번 이내로 제한" |
| LOGIN-3 | 실패 횟수를 세션이나 쿠키에 저장한다 | 횟수를 적는 줄 | 진단가이드 p.111, p.563 "인증 시도 정보를 DB에 기록", OWASP "계정 자체에 연결" |
| LOGIN-4 | 잠금 확인을 거치지 않고 비밀번호를 확인한다 (잠긴 계정도 비밀번호만 맞으면 통과) | 비밀번호를 확인하는 줄 | Python 가이드 p.116 "초과할 경우 계정을 잠금", 진단가이드 p.563 |

- 횟수 제한으로 인정하는 것: 저장소(DB, 서버의 변수, 세션)에서 읽은 값을 숫자와 비교(`>=`, `>`, `<`, `<=`)하는 곳. 비교식에 쓰인 이름 가운데 횟수를 뜻하는 낱말(`fail` `attempt` `try` `count` `lock` `limit` `max`, `실패` `횟수` `잠금` 등)이 있어야 한다. 시간을 뜻하는 낱말(`time` `seconds` 등)이 있으면 경과 시간 비교로 보고 제외한다. 이름으로 판단하는 부분은 **해석**이다.
- LOGIN-2: `횟수 >= N`이면 허용 횟수는 N, `횟수 > N`이면 N+1이다. N이 상수가 아니면 확인할 수 없는 것으로 본다.
- LOGIN-3: Flask의 세션은 브라우저 쿠키에 담기므로 쿠키를 지우면 횟수가 0으로 돌아간다. 서버의 변수(모듈 최상위 dict)나 DB에 저장하는 것은 걸리지 않는다.
- LOGIN-4: 비밀번호를 확인하는 지점에 "횟수 비교를 통과했다"는 사실이 없으면 걸린다.
  - **Python 가이드 p.117~118의 안전한 예제는 이 규칙에 걸린다.** 그 예제는 비밀번호가 맞으면 횟수와 관계없이 로그인시키므로, 잠긴 뒤에도 계속 비밀번호를 넣어 볼 수 있다. 같은 가이드의 본문(p.116)은 횟수를 넘으면 계정을 잠그라고 하므로 본문을 따랐다.
- `@limiter.limit("5 per minute")`(flask_limiter)가 그 라우트에 붙어 있으면 그것으로 판정한다. 횟수가 5를 넘거나 단위가 초이면 LOGIN-2(데코레이터 줄), 아니면 안전이다. Python 가이드 p.116은 요청 제한 모듈 사용을 대안으로 든다.

## 5. 학생 응답 흐름

### 5.1 IDOR

- 1차 호출 `analyze(code)` 또는 `analyze(code, {})`: 보호되지 않은 후보 라우트가 있으면 `verdict: null`과 질문을 돌려준다.

```json
{"type": "idor_routes", "question": "이 페이지에 나오는 정보는 로그인한 본인만 봐야 하나요?",
 "routes": [{"function": "edit", "route": "/edit/<int:post_id>", "line": 125}]}
```

- 2차 호출 `analyze(code, {"idor": {"public_functions": ["detail"]}})`: `public_functions`에 없는 후보는 "본인만"으로 보고 IDOR-1~4를 판정한다. 목록에 있는 함수는 공개 페이지이므로 걸리지 않는다.
- `line`은 그 라우트의 데코레이터 줄이다.

### 5.2 SSRF

- SSRF-1이 있고 응답이 없으면 판정(위험)과 함께 질문을 돌려준다.

```json
{"type": "ssrf_dynamic_request", "question": "사용자가 준 주소로 서버가 꼭 요청해야 하는 기능인가요?"}
```

- `{"ssrf": {"dynamic_request_needed": true}}`로 답하면 `acknowledged: true`가 된다. 판정은 위험 그대로다. Python 가이드 p.55는 임의의 주소를 받아야만 하는 경우 내부 주소를 차단하라고 한다.

## 6. 결과 형식

```json
{"ok": true, "results": [
  {"vuln_id": "sql_injection", "verdict": "위험",
   "findings": [{"rule_id": "SQL-1", "line": 13, "path": [11, 13], "message": "…"}],
   "needs_user_input": null, "acknowledged": false}
]}
```

- `results`는 1장의 순서대로 항상 10개다.
- `verdict`: `"안전"`, `"위험"`, 또는 질문에 답하기 전이면 `null`.
- 문법 오류가 있으면 `{"ok": false, "error": {"line": 3, "message": "3번째 줄에 문법 오류가 있어요."}}`.
- 줄 번호는 BOM을 떼고 줄바꿈을 `\n`으로 통일한 글 기준이다.

## 부록 A. 규칙별 메시지

`detector/result.py`의 `MESSAGES`가 원본이다.

## 부록 B. 가이드에 있지만 적용하지 않은 것

| 내용 | 적용하지 않은 이유 |
|---|---|
| 업로드 파일의 크기·개수 제한 (Python 가이드 p.33, 진단가이드 p.95) | 수정 방법 표(카드)에 없는 규칙이라 넣지 않았다. 넣으려면 규칙·카드·화면을 함께 정해야 한다 |
| 사용자 정의 에러 페이지가 없음 (Python 가이드 p.126의 Django 예제) | Flask는 디버그 모드가 꺼져 있으면 기본 오류 화면에 내부 정보를 내보내지 않는다. 실제 실행으로 확인했다 (500 응답 265 bytes, 경로·코드·SQL 없음) |
| 업로드 파일을 웹 루트 밖에 저장, 무작위 이름, 실행 권한 제거 (Python 가이드 p.33) | 저장 위치와 권한은 코드 한 파일로 판정할 수 없다 |
| 자원 삽입: 소켓 포트 등 (Python 가이드 p.20) | 선정한 10종의 "경로 조작" 범위 밖 |
| 중요정보 평문 전송 (Python 가이드 p.83) | 선정한 10종의 범위 밖 |
| 주석 안의 아이디 (Python 가이드 p.109의 `# id = admin`) | `id = …` 형태의 주석은 대부분 코드 설명이라 구분할 수 없다. 비밀번호·키만 본다 |
| 비밀번호 조합 규칙 (Python 가이드 p.94), 인증 실패 기록 로깅 (진단가이드 p.509 SR2-2 ②), CAPTCHA·2단계 인증 (Python 가이드 p.116) | 10번 항목의 범위를 "반복된 인증시도 제한"으로 정했다 |

## 부록 C. 가이드 밖에서 확인한 자료 (2026-11-24 확인)

1. OWASP, Insecure Direct Object Reference Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
   - IDOR는 접근 제어 확인이 빠져서 생긴다. 사용자가 접근하려는 객체마다 접근 제어를 확인한다. 현재 사용자는 세션 정보로 판단한다. 복잡한 식별자는 보조 수단일 뿐이다.
2. OWASP, Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
   - 권장 순서: Argon2id, scrypt, bcrypt(기존 시스템), PBKDF2(FIPS 필요 시). 비밀번호마다 고유한 솔트. 평문 저장 금지.
3. OWASP, Authentication Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
   - 실패 횟수는 접속 주소가 아니라 계정 자체에 연결한다. 허용 횟수의 구체적인 숫자와 저장 위치는 적혀 있지 않다. 숫자(3~5번)는 진단가이드 p.110에서 가져왔다.
4. Werkzeug 문서, Utilities. https://werkzeug.palletsprojects.com/en/stable/utils/
   - `secure_filename()`: 파일 이름을 일반 파일 시스템과 `os.path.join()`에 쓰기 안전하게 바꾼다.
   - `safe_join()`: 기준 폴더를 벗어나는 경로면 `None`을 돌려준다. `send_from_directory()`는 `safe_join()`을 쓴다.
   - `generate_password_hash()`: 기본 방식 scrypt, 그 밖에 pbkdf2. 솔트 길이 기본 16.
5. Flask 문서, Uploading Files. https://flask.palletsprojects.com/en/stable/patterns/fileuploads/
   - `allowed_file()`로 확장자를 제한한다. 저장 전에 항상 `secure_filename()`을 쓴다.
   - Flask 문서, API의 `send_file`: 사용자가 준 경로를 넘기지 말고 `send_from_directory()`를 쓴다. https://flask.palletsprojects.com/en/stable/api/
6. Flask 문서, Debugging Application Errors. https://flask.palletsprojects.com/en/stable/debugging/
   - 운영 환경에서 개발 서버와 디버거를 켜지 않는다. 디버거는 브라우저에서 임의의 파이썬 코드를 실행할 수 있다.
