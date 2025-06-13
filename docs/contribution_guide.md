## 🤝 Git & GitHub 협업 가이드 

### 👥 협업 규칙

- **가상환경(venv)과 .env 파일은 Git에 올리지 마세요!**
- 기능 추가/수정은 반드시 브랜치 생성 후 Pull Request로 병합
- 코드 리뷰/테스트 통과 후 main 브랜치에 반영

### 1. 기능 개발 시작: 브랜치 생성하고 이동

```
git switch -c feature/내기능이름
```

**🌿 브랜치명 규칙**
- 브랜치명은 아래 형식을 권장합니다.
    - `feature/기능명` (새 기능)
    - `bugfix/이슈번호-설명` (버그 수정)
    - `docs/문서명` (문서)
    - `test/설명` (테스트)
- 예시:
    - `feature/github-api-integration`
    - `bugfix/34-filter-extension-error`
    - `docs/update-readme`

### 2. 코드 수정 → 변경사항 저장 (commit)

```
git add .
git commit -m "Add: GitHub API 연동 기능 추가"
```

**📝 커밋 메시지 규칙**
- 커밋 메시지는 아래 형식을 지켜주세요.
    - `Add: ...` (새 기능)
    - `Fix: ...` (버그 수정)
    - `Update: ...` (기존 코드/문서/설정 변경)
    - `Remove: ...` (삭제)
    - `Refactor: ...` (구조 개선)
    - `Docs: ...` (문서)
    - `Test: ...` (테스트)
    - `Chore: ...` (환경/설정)
- 예시:
    - `Add: SAST 실행 기능 구현`
    - `Fix: 파일 필터링 버그 수정`
    - `Docs: README 업데이트`

### 3. GitHub에 업로드 (push)

```
git push origin feature/github-api-integration
```

### 4. 다른 사람 코드와 충돌 방지 (pull)

```
git pull origin dev
```

> 💡 최신 dev 브랜치 내용을 내 브랜치에 반영

### 5. GitHub에서 Pull Request 만들기

- GitHub에서 Compare & pull request 버튼 클릭
- base는 dev, compare는 내 브랜치인지 확인
- 제목/설명 작성 후 Create pull request

### 6. 팀장이 Merge 완료 후 dev 최신화

```
git switch dev
git pull origin dev
``` 

> 💡 Merge가 끝났다면 dev 브랜치에서도 최신 상태를 유지해야 해요!

> 다음 기능 개발 시 1번부터터 반복합니다. 