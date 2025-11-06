#!/usr/bin/env python3
"""
SAST XML 생성 CLI

사용 예:
    python -m autofic_core.sast.cli generate \
        --input artifacts/downloaded_repo/sast/merged_snippets.json \
        --output artifacts/CUSTOM_CONTEXT.xml \
        --validate
    
    python -m autofic_core.sast.cli validate \
        --xml artifacts/CUSTOM_CONTEXT.xml \
        --schema custom_context.xsd
"""
import argparse
import logging
import sys
from pathlib import Path

from autofic_core.sast.workflow import SASTXMLWorkflow, create_custom_context_xml
from autofic_core.sast.xml_validator import check_xmlschema_available
from autofic_core.sast.xml_generator import RenderOptions

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_generate(args):
    """XML 생성 커맨드"""
    input_path = Path(args.input)
    output_path = Path(args.output)
    schema_path = Path(args.schema) if args.schema else None
    
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        return 1
    
    # 옵션 설정
    options = RenderOptions(
        tool_name=args.tool_name,
        schema_location=args.schema_location,
        include_env=not args.no_env,
        include_tracking=not args.no_tracking,
        include_mitigations=not args.no_mitigations,
        context_lines_before=args.context_before,
        context_lines_after=args.context_after,
    )
    
    try:
        xml_path = create_custom_context_xml(
            merged_snippets_path=input_path,
            output_xml_path=output_path,
            schema_path=schema_path,
            validate=args.validate,
            options=options,
        )
        
        logger.info(f"✓ Successfully generated: {xml_path}")
        return 0
    
    except Exception as e:
        logger.error(f"✗ Failed to generate XML: {e}", exc_info=True)
        return 1


def cmd_validate(args):
    """XML 검증 커맨드"""
    xml_path = Path(args.xml)
    schema_path = Path(args.schema) if args.schema else None
    
    if not xml_path.exists():
        logger.error(f"XML file not found: {xml_path}")
        return 1
    
    if not check_xmlschema_available():
        logger.error("xmlschema package is not installed")
        logger.error("Install it with: pip install xmlschema")
        return 1
    
    try:
        workflow = SASTXMLWorkflow(schema_path=schema_path, auto_validate=False)
        is_valid = workflow.validate_existing_xml(xml_path)
        
        if is_valid:
            logger.info("✓ Validation passed")
            return 0
        else:
            logger.error("✗ Validation failed")
            return 1
    
    except Exception as e:
        logger.error(f"✗ Validation error: {e}", exc_info=True)
        return 1


def cmd_info(args):
    """정보 출력 커맨드"""
    print("AutoFiC SAST XML Generator")
    print("=" * 50)
    print(f"xmlschema available: {check_xmlschema_available()}")
    
    schema_path = Path(args.schema) if args.schema else None
    if schema_path and schema_path.exists():
        try:
            from autofic_core.sast.xml_validator import XMLValidator
            validator = XMLValidator(schema_path)
            info = validator.get_schema_info()
            
            print(f"\nSchema Information:")
            print(f"  Path: {info['schema_path']}")
            print(f"  Namespace: {info['target_namespace']}")
            print(f"  Elements: {len(info['elements'])}")
            print(f"  Types: {len(info['types'])}")
        except Exception as e:
            print(f"\nFailed to load schema: {e}")
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="AutoFiC SAST XML Generator and Validator"
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # generate 커맨드
    gen_parser = subparsers.add_parser('generate', help='Generate CUSTOM_CONTEXT.xml')
    gen_parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input merged_snippets.json path'
    )
    gen_parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output CUSTOM_CONTEXT.xml path'
    )
    gen_parser.add_argument(
        '--schema', '-s',
        help='XSD schema path (default: custom_context.xsd in project root)'
    )
    gen_parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate generated XML against schema'
    )
    gen_parser.add_argument(
        '--tool-name',
        default='AutoFiC-SAST',
        help='Tool name in META element'
    )
    gen_parser.add_argument(
        '--schema-location',
        default='schemas/custom_context.xsd',
        help='Schema location in XML'
    )
    gen_parser.add_argument(
        '--no-env',
        action='store_true',
        help='Exclude ENV elements'
    )
    gen_parser.add_argument(
        '--no-tracking',
        action='store_true',
        help='Exclude TRACKING elements'
    )
    gen_parser.add_argument(
        '--no-mitigations',
        action='store_true',
        help='Exclude MITIGATION elements'
    )
    gen_parser.add_argument(
        '--context-before',
        type=int,
        default=3,
        help='Context lines before (default: 3)'
    )
    gen_parser.add_argument(
        '--context-after',
        type=int,
        default=3,
        help='Context lines after (default: 3)'
    )
    
    # validate 커맨드
    val_parser = subparsers.add_parser('validate', help='Validate XML against schema')
    val_parser.add_argument(
        '--xml', '-x',
        required=True,
        help='XML file to validate'
    )
    val_parser.add_argument(
        '--schema', '-s',
        help='XSD schema path (default: custom_context.xsd in project root)'
    )
    
    # info 커맨드
    info_parser = subparsers.add_parser('info', help='Show information')
    info_parser.add_argument(
        '--schema', '-s',
        help='XSD schema path to inspect'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # 커맨드 실행
    if args.command == 'generate':
        return cmd_generate(args)
    elif args.command == 'validate':
        return cmd_validate(args)
    elif args.command == 'info':
        return cmd_info(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
