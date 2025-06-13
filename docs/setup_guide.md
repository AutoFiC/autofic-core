## 🚀 개발 환경 세팅 

### 1. Python 설치
- [Python 공식 다운로드](https://www.python.org/downloads/)
- **Python 3.8 이상** 설치 권장
- 설치 시 "Add Python to PATH" 옵션 반드시 체크

### 2. Git 설치 및 레포지토리 클론
- [Git 다운로드](https://git-scm.com/downloads)
- 터미널/명령 프롬프트/PowerShell/터미널 앱에서:
    ```
    git clone https://github.com/AutoFiC/autofic-core.git
    cd autofic-core
    ```

### 3. 가상환경(venv) 생성 및 활성화

- Windows (CMD)
    ```
    python -m venv venv
    venv\Scripts\activate
    ```

-  Windows (PowerShell)
    ```
    python -m venv venv
    .\venv\Scripts\activate
    ```

- Windows (Git Bash)
    ```
    python -m venv venv
    source venv/Scripts/activate
    ```

- macOS / Linux (터미널)
    ```
    python3 -m venv venv
    source venv/bin/activate
    ```

> 가상환경이 활성화되면 프롬프트 앞에 `(venv)`가 표시됩니다.

### 4. pip 최신화 (권장) 
```
pip install --upgrade pip
```

### 5. 필수 라이브러리 및 개발 모드 설치
```
pip install -r requirements.txt
pip install -e . 
```
> -e는 editable 모드입니다. 소스코드를 수정하면 바로 반영되어 개발에 편리합니다.

### 6. 환경변수 파일 준비
```
cp .env.example .env
``` 

> `.env` 파일에 본인의 GitHub 토큰, OpenAI API 키 등 필요한 값을 입력하세요.

<br> 

## ⚡ 실행 방법

### 1. CLI 직접 실행

```
python -m autofic_core.cli --repo https://github.com/AutoFiC/autofic-core.git
```

### 2. 명령어로 실행 (개발 모드 설치 후) 

```
autofic-core --repo https://github.com/AutoFiC/autofic-core.git
```

<br> 

## 🧪 테스트 방법

```
pytest tests/ 
``` 

- 모든 테스트가 **passed** 되면 정상 

<br> 

## 📁 주요 파일 설명

| 파일/폴더             | 설명                                      |
|-----------------------|-------------------------------------------|
| src/autofic_core/     | 핵심 기능 Python 소스코드                  |
| tests/                | 테스트 코드                                |
| requirements.txt      | 필수 라이브러리 목록                       |
| pyproject.toml        | 패키지/배포/엔트리포인트 설정              |
| .env.example          | 환경변수 템플릿 (실제 값은 .env에 입력)    |
| .gitignore            | Git에 올리지 않을 파일/폴더 목록           |
| LICENSE               | 오픈소스 라이선스(MIT)           |
| README.md             | 이 문서                                    |