import json
from pathlib import Path
from typing import Tuple, Optional
import logging
from jsonschema import validate, ValidationError

logger = logging.getLogger(__name__)


class SchemaValidator:
    
    def __init__(self, schema_path: Path):
        self.schema_path = schema_path
        self.schema = self._load_schema()
    
    def _load_schema(self) -> dict:
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {self.schema_path}")
        
        with open(self.schema_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def validate_file(self, json_file: Path) -> Tuple[bool, Optional[str]]:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            validate(instance=data, schema=self.schema)
            logger.debug(f"Schema validation passed: {json_file}")
            return True, None
            
        except ValidationError as e:
            error_msg = f"Schema validation failed: {e.message} at path {list(e.path)}"
            logger.error(error_msg)
            return False, error_msg
            
        except Exception as e:
            error_msg = f"Validation error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def move_to_invalid(self, json_file: Path, invalid_dir: Path) -> Path:

        invalid_dir.mkdir(parents=True, exist_ok=True)
        invalid_path = invalid_dir / json_file.name
        
        json_file.rename(invalid_path)
        logger.info(f"Moved invalid file to: {invalid_path}")
        
        return invalid_path