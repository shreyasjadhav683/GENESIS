import os
import hashlib
import json
import logging
from typing import Dict, List, Any, Tuple
from pathlib import Path
import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASELINE_DIR = Path("baselines")
BASELINE_DIR.mkdir(exist_ok=True)

class FileIntegrityService:
    def __init__(self):
        self.baseline_dir = Path("baselines")
        self.baseline_dir.mkdir(exist_ok=True)

    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculates SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Read 64kb chunks
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, OSError):
            return "ACCESS_DENIED"

    def _simplify_path(self, path: str) -> str:
        """Creates a safe filename from a path."""
        return hashlib.md5(path.encode()).hexdigest()

    def create_baseline(self, target_path: str) -> Dict[str, Any]:
        """Scans a single file and saves a baseline snapshot."""
        path_obj = Path(target_path)
        
        # Enforce file only
        if not path_obj.exists():
             raise ValueError(f"File not found: {target_path}")
        if not path_obj.is_file():
            raise ValueError(f"Target must be a file, not a directory: {target_path}")

        logger.info(f"Starting baseline creation for {target_path}")

        file_hash = self._calculate_file_hash(str(path_obj))
        if file_hash == "ACCESS_DENIED":
             raise PermissionError(f"Access denied to file: {target_path}")

        baseline_data = {
            "target_path": str(path_obj.absolute()),
            "timestamp": datetime.datetime.now().isoformat(),
            "file_name": path_obj.name,
            "size": path_obj.stat().st_size,
            "hash": file_hash
        }

        # Save to disk
        baseline_id = self._simplify_path(str(path_obj.absolute()))
        output_file = self.baseline_dir / f"{baseline_id}.json"
        
        with open(output_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)

        return baseline_data

    def verify_integrity(self, target_path: str) -> Dict[str, Any]:
        """Compares current state of the file against last baseline."""
        path_obj = Path(target_path)
        
        if not path_obj.exists():
            # If file doesn't exist now but we have a baseline, it's REMOVED (or just gone)
            pass 
        elif not path_obj.is_file():
             raise ValueError(f"Target must be a file: {target_path}")

        baseline_id = self._simplify_path(str(path_obj.absolute()))
        baseline_file = self.baseline_dir / f"{baseline_id}.json"

        if not baseline_file.exists():
            raise FileNotFoundError("No baseline found for this file. Please create one first.")

        with open(baseline_file, 'r') as f:
            baseline = json.load(f)

        current_hash = None
        status = "CLEAN"
        details = "File is unchanged."

        if not path_obj.exists():
            status = "REMOVED"
            details = "File has been deleted."
        else:
            current_hash = self._calculate_file_hash(str(path_obj))
            if current_hash == "ACCESS_DENIED":
                status = "ERROR"
                details = "Access denied during verification."
            elif current_hash != baseline["hash"]:
                status = "MODIFIED"
                details = "File content has changed."
        
        return {
            "status": status,
            "target_path": target_path,
            "last_baseline": baseline["timestamp"],
            "scan_time": datetime.datetime.now().isoformat(),
            "details": details,
            "baseline_hash": baseline["hash"],
            "current_hash": current_hash
        }

file_integrity_service = FileIntegrityService()
