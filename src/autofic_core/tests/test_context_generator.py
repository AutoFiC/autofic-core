"""ContextGenerator 단독 테스트"""

from pathlib import Path
from autofic_core.sast.snippet import BaseSnippet
from autofic_core.annotation.context_generator import ContextGenerator


def test_context_generator_basic():
    """기본 XML 생성 테스트"""
    
    # 1. 테스트 스니펫 생성
    snippet = BaseSnippet(
        path="core/appHandler.js",
        start_line=11,
        end_line=11,
        snippet="db.sequelize.query(query, {",
        message="SQL Injection vulnerability",
        severity="HIGH",
        bit_trigger="User input flows to SQL query",
        bit_steps=["Review line 11"],
        bit_reproduction="Test with SQL injection payload",
        bit_severity="HIGH"
    )
    
    # 2. XML 생성
    generator = ContextGenerator(tool_name="TestTool")
    output_path = Path("test_output/CUSTOM_CONTEXT.xml")
    output_path.parent.mkdir(exist_ok=True)
    
    try:
        result_path = generator.generate([snippet], output_path)
        
        # 3. 검증
        assert result_path.exists(), "XML 파일이 생성되지 않음"
        
        # 4. 내용 확인
        with open(result_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert 'CUSTOM_CONTEXT' in content, "루트 요소 없음"
        assert 'VULNERABILITY' in content, "VULNERABILITY 요소 없음"
        assert 'core/appHandler.js' in content, "파일 경로 없음"
        assert 'SQL Injection' in content, "메시지 없음"
        assert 'BIT' in content, "BIT 요소 없음"
        assert 'User input flows' in content, "Trigger 없음"
        
        print("✅ ContextGenerator 기본 테스트 통과!")
        print(f"생성된 파일: {result_path}")
        print(f"\n첫 500자:\n{content[:500]}")
        
        return True
        
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_context_generator_basic()
    exit(0 if success else 1)