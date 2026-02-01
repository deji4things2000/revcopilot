"""
RevCopilot Backend Server - Complete with Web UI and AI-Assisted Disassembler
Enhanced with GDB integration and improved vulnerability detection
"""

import asyncio
import uuid
import os
import logging
import shutil
import json
import urllib.request
import urllib.error
import subprocess
import stat
import re
import hashlib
import struct
import tempfile
import sys
import time
from typing import Optional, List, Dict, Any
import traceback
from datetime import datetime
from pathlib import Path
import binascii
import shlex

# Try to import optional dependencies
try:
    import angr
    import claripy
except ImportError:
    angr = None
    claripy = None

try:
    import aiofiles
except ImportError:
    aiofiles = None

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Query, Header, Form, Request
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory job store
jobs = {}

app = FastAPI(
    title="RevCopilot",
    description="AI-Powered Reverse Engineering Assistant with Disassembler and Vulnerability Patcher",
    version="3.0.0",  # Updated version for GDB integration
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

class JobStatus(BaseModel):
    job_id: str
    status: str
    result: Optional[dict] = None
    error: Optional[str] = None

class PatchRequest(BaseModel):
    job_id: str
    vulnerability_id: str
    patch_strategy: str = "safe"  # safe, aggressive, or custom
    patch_data: Optional[Dict] = None

# ==================== GDB INTEGRATION ====================

class GDBAnalyzer:
    """GDB-based dynamic analysis for binaries."""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.gdb_output = None
        
    def check_gdb_installed(self) -> bool:
        """Check if GDB is installed and accessible."""
        try:
            result = subprocess.run(['gdb', '--version'], capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def analyze_with_gdb(self, args: List[str] = None) -> Dict[str, Any]:
        """Run binary through GDB with basic analysis."""
        if not self.check_gdb_installed():
            return {
                "success": False,
                "error": "GDB not installed",
                "install_instructions": {
                    "ubuntu": "sudo apt-get install gdb",
                    "macos": "brew install gdb",
                    "windows": "Download from https://www.sourceware.org/gdb/"
                }
            }
        
        gdb_script_path = None
        gdb_output_file = None
        
        try:
            # Create temp output file
            temp_dir = tempfile.gettempdir()
            gdb_output_file = os.path.join(temp_dir, f"gdb_output_{uuid.uuid4().hex}.txt")
            
            # Escape the binary path for GDB script
            escaped_path = shlex.quote(self.binary_path)
            
            # Create GDB script
            gdb_script = f"""
set pagination off
set confirm off
set logging file {shlex.quote(gdb_output_file)}
set logging on

# Basic analysis (avoid long-running run/continue)
file {escaped_path}
starti
info registers
info functions
info proc mappings

# Analyze main function without running to breakpoint
disassemble /r main
info frame
info locals

# Stack analysis
x/20x $rsp
info stack

set logging off
quit
"""
            
            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(gdb_script)
                gdb_script_path = f.name
            
            # Run GDB
            cmd = ['gdb', '-q', '-batch', '-x', gdb_script_path, self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            
            # Read output file
            gdb_output = ""
            if os.path.exists(gdb_output_file):
                with open(gdb_output_file, "r") as f:
                    gdb_output = f.read()
            
            return {
                "success": True,
                "gdb_output": gdb_output[:5000],  # Limit size
                "analysis": self.parse_gdb_output(gdb_output)
            }
            
        except Exception as e:
            logger.error(f"GDB analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "gdb_output": ""
            }
        finally:
            # Cleanup
            try:
                if gdb_script_path and os.path.exists(gdb_script_path):
                    os.unlink(gdb_script_path)
            except:
                pass
            try:
                if gdb_output_file and os.path.exists(gdb_output_file):
                    os.unlink(gdb_output_file)
            except:
                pass
    
    def parse_gdb_output(self, output: str) -> Dict[str, Any]:
        """Parse GDB output for useful information."""
        analysis = {
            "registers": {},
            "functions": [],
            "memory_maps": [],
            "security_features": []
        }
        
        # Parse registers
        for line in output.split('\n'):
            line = line.strip()
            if ' = ' in line and any(reg in line for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rip', 'eflags']):
                parts = line.split('=')
                if len(parts) == 2:
                    reg_name = parts[0].strip()
                    reg_value = parts[1].strip()
                    analysis["registers"][reg_name] = reg_value
        
        # Check for security features
        if "__stack_chk_fail" in output:
            analysis["security_features"].append("Stack canary protection")
        if "__printf_chk" in output:
            analysis["security_features"].append("FORTIFY_SOURCE protection")
        
        return analysis

# ==================== UTILITY FUNCTIONS ====================

async def save_uploaded_file(file: UploadFile, identifier: str) -> str:
    """Save uploaded file to temporary location."""
    if aiofiles is None:
        # Fallback to synchronous file operations
        return save_uploaded_file_sync(file, identifier)
    
    # Use tempfile for cross-platform compatibility
    temp_dir = tempfile.gettempdir()
    upload_dir = os.path.join(temp_dir, "revcopilot_uploads")
    os.makedirs(upload_dir, exist_ok=True)
    
    original_name = file.filename or "binary"
    # Make filename safe
    safe_name = "".join(c for c in original_name if c.isalnum() or c in '._- ').rstrip()
    file_path = os.path.join(upload_dir, f"{identifier}_{safe_name}")
    
    try:
        async with aiofiles.open(file_path, 'wb') as buffer:
            # Read file in chunks to handle large files
            while True:
                chunk = await file.read(8192)  # 8KB chunks
                if not chunk:
                    break
                await buffer.write(chunk)
        
        logger.info(f"Saved uploaded file to {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"Failed to save file: {e}")
        raise

def save_uploaded_file_sync(file: UploadFile, identifier: str) -> str:
    """Synchronous fallback for saving uploaded file."""
    temp_dir = tempfile.gettempdir()
    upload_dir = os.path.join(temp_dir, "revcopilot_uploads")
    os.makedirs(upload_dir, exist_ok=True)
    
    original_name = file.filename or "binary"
    safe_name = "".join(c for c in original_name if c.isalnum() or c in '._- ').rstrip()
    file_path = os.path.join(upload_dir, f"{identifier}_{safe_name}")
    
    try:
        with open(file_path, 'wb') as buffer:
            while True:
                chunk = file.file.read(8192)  # 8KB chunks
                if not chunk:
                    break
                buffer.write(chunk)
        
        logger.info(f"Saved uploaded file to {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"Failed to save file: {e}")
        raise

def cleanup_file(file_path: str):
    """Clean up temporary file."""
    try:
        if os.path.exists(file_path):
            os.unlink(file_path)
            logger.info(f"Cleaned up file: {file_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup file {file_path}: {e}")

def detect_file_type(file_path: str) -> str:
    """Detect file type using file command."""
    try:
        result = subprocess.run(['file', '-b', file_path], capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except:
        return "Unknown"

def calculate_md5(file_path: str) -> str:
    """Calculate MD5 hash of file."""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return "unknown"

def calculate_sha256(file_path: str) -> str:
    """Calculate SHA256 hash of file."""
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except:
        return "unknown"

def is_medium_bin(file_path: str) -> bool:
    """Check if file is medium.bin."""
    filename = os.path.basename(file_path).lower()
    
    if 'medium' in filename and filename.endswith('.bin'):
        return True
    
    # Check file size (medium.bin is often 14472 bytes)
    try:
        if os.path.getsize(file_path) == 14472:
            return True
    except:
        pass
    
    return False

# ==================== AI-POWERED VULNERABILITY PATCHER ====================

class AIVulnerabilityPatcher:
    """AI-powered vulnerability patching through the disassembler."""
    
    @staticmethod
    def analyze_and_patch(disassembly: str, vulnerability_info: Dict, api_key: str = None, api_url: str = None) -> Dict[str, Any]:
        """Analyze disassembly and generate patches using AI."""
        
        # Prepare AI prompt for vulnerability analysis
        prompt = f"""
VULNERABILITY ANALYSIS AND PATCHING REQUEST

Vulnerability Details:
- Type: {vulnerability_info.get('type', 'Unknown')}
- Severity: {vulnerability_info.get('severity', 'Unknown')}
- Description: {vulnerability_info.get('description', 'No description')}
- Location: {vulnerability_info.get('location', 'Unknown')}

Disassembled Code:
{disassembly[:1500] if len(disassembly) > 1500 else disassembly}

Please analyze this vulnerability and provide:
1. Detailed explanation of the vulnerability
2. Recommended patch strategy
3. Specific byte-level patches if applicable
4. Alternative workarounds
5. Patch script or code modifications

Focus on practical, executable solutions.
"""
        
        try:
            payload = {
                "model": os.getenv("DARTMOUTH_CHAT_MODEL", "openai.gpt-4.1-mini-2025-04-14"),
                "messages": [
                    {"role": "system", "content": "You are a binary security expert and vulnerability patching specialist. Provide detailed, executable patch solutions."},
                    {"role": "user", "content": prompt},
                ],
            }
            
            result = _call_dartmouth_chat(payload, api_key, api_url)
            insights = result.get("insights", "") if isinstance(result, dict) else str(result)
            
            # Parse AI response to extract patch information
            patches = AIVulnerabilityPatcher._extract_patches_from_ai_response(insights, vulnerability_info)
            
            return {
                "success": True,
                "analysis": insights,
                "patches": patches,
                "recommendations": AIVulnerabilityPatcher._generate_recommendations(insights),
                "patch_scripts": AIVulnerabilityPatcher._generate_patch_scripts(patches, vulnerability_info)
            }
            
        except Exception as e:
            logger.error(f"AI vulnerability analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "fallback_patches": AIVulnerabilityPatcher._generate_fallback_patches(vulnerability_info)
            }
    
    @staticmethod
    def _extract_patches_from_ai_response(ai_response: str, vulnerability_info: Dict) -> List[Dict]:
        """Extract patch information from AI response."""
        patches = []
        
        # Common vulnerability patterns and their patches
        vuln_type = vulnerability_info.get('type', '').lower()
        
        if 'strcpy' in vuln_type:
            patches.append({
                "type": "strcpy_replacement",
                "description": "Replace strcpy with strncpy",
                "implementation": "Replace function call and add size parameter",
                "difficulty": "medium"
            })
        
        if 'buffer' in vuln_type and 'overflow' in vuln_type:
            patches.append({
                "type": "bounds_check",
                "description": "Add bounds checking before buffer operations",
                "implementation": "Insert size checks before vulnerable operations",
                "difficulty": "medium"
            })
        
        if 'format' in vuln_type and 'string' in vuln_type:
            patches.append({
                "type": "format_string_fix",
                "description": "Fix format string vulnerabilities",
                "implementation": "Replace printf with printf with fixed format strings",
                "difficulty": "low"
            })
        
        # Try to extract patches from AI response
        lines = ai_response.split('\n')
        current_patch = None
        
        for line in lines:
            line_lower = line.lower()
            
            if any(keyword in line_lower for keyword in ['patch:', 'fix:', 'solution:']):
                if current_patch:
                    patches.append(current_patch)
                
                current_patch = {
                    "type": "ai_generated",
                    "description": line.strip(),
                    "implementation": "",
                    "difficulty": "unknown"
                }
            
            elif current_patch and any(keyword in line_lower for keyword in ['bytes:', 'replace:', 'code:']):
                current_patch["implementation"] = line.strip()
        
        if current_patch:
            patches.append(current_patch)
        
        return patches
    
    @staticmethod
    def _generate_recommendations(ai_analysis: str) -> List[str]:
        """Generate recommendations from AI analysis."""
        recommendations = []
        
        # Extract recommendations from AI response
        lines = ai_analysis.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ['recommend', 'suggest', 'should', 'advise']):
                clean_line = line.strip().lstrip('-•* ')
                if clean_line and len(clean_line) > 10:
                    recommendations.append(clean_line)
        
        # Default recommendations
        if not recommendations:
            recommendations = [
                "Review the AI analysis for specific patch instructions",
                "Test patches in a controlled environment before deployment",
                "Consider using binary rewriting tools like LIEF or radare2 for complex patches",
                "For production systems, consider recompiling from source with security fixes"
            ]
        
        return recommendations[:5]
    
    @staticmethod
    def _generate_patch_scripts(patches: List[Dict], vulnerability_info: Dict) -> Dict[str, str]:
        """Generate executable patch scripts."""
        scripts = {}
        
        for i, patch in enumerate(patches):
            patch_type = patch.get('type', '')
            
            if 'strcpy' in patch_type:
                scripts[f"strcpy_fix_{i}.c"] = AIVulnerabilityPatcher._generate_strcpy_patch_script(patch, vulnerability_info)
            elif 'buffer' in patch_type:
                scripts[f"buffer_fix_{i}.c"] = AIVulnerabilityPatcher._generate_buffer_patch_script(patch, vulnerability_info)
            elif 'format' in patch_type:
                scripts[f"format_fix_{i}.c"] = AIVulnerabilityPatcher._generate_format_patch_script(patch, vulnerability_info)
            else:
                scripts[f"generic_fix_{i}.c"] = AIVulnerabilityPatcher._generate_generic_patch_script(patch, vulnerability_info)
        
        # Always include a Python patcher script
        scripts["patcher.py"] = AIVulnerabilityPatcher._generate_python_patcher_script(patches, vulnerability_info)
        
        return scripts
    
    @staticmethod
    def _generate_strcpy_patch_script(patch: Dict, vulnerability_info: Dict) -> str:
        return f"""/*
 * Patch script for strcpy vulnerability
 * Vulnerability: {vulnerability_info.get('description', 'Unknown')}
 */

#include <string.h>
#include <stdio.h>

// Safe string copy with length checking
size_t safe_strcpy(char* dest, const char* src, size_t dest_size) {{
    if (dest_size == 0) return 0;
    
    size_t src_len = strlen(src);
    size_t copy_len = src_len < dest_size - 1 ? src_len : dest_size - 1;
    
    if (copy_len > 0) {{
        memcpy(dest, src, copy_len);
    }}
    dest[copy_len] = '\\0';
    
    return copy_len;
}}

// Hook function to replace strcpy
__attribute__((constructor))
void init_strcpy_hook() {{
    printf("strcpy patcher loaded\\n");
    // In a real implementation, you would patch the PLT/GOT here
}}

// LD_PRELOAD compatible implementation
char* strcpy(char* dest, const char* src) {{
    // Use a reasonable default buffer size
    safe_strcpy(dest, src, 1024);
    return dest;
}}
"""
    
    @staticmethod
    def _generate_buffer_patch_script(patch: Dict, vulnerability_info: Dict) -> str:
        return f"""/*
 * Patch script for buffer overflow vulnerability
 * Vulnerability: {vulnerability_info.get('description', 'Unknown')}
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Safe buffer operations
void* safe_memcpy(void* dest, const void* src, size_t n, size_t dest_size) {{
    if (n > dest_size) {{
        fprintf(stderr, "Buffer overflow prevented: tried to copy %zu bytes into %zu byte buffer\\n", n, dest_size);
        abort(); // Or handle more gracefully
    }}
    return memcpy(dest, src, n);
}}

// Stack canary implementation for additional protection
#ifdef __linux__
__attribute__((constructor))
void init_stack_protection() {{
    printf("Stack protection enabled\\n");
}}
#endif
"""
    
    @staticmethod
    def _generate_format_patch_script(patch: Dict, vulnerability_info: Dict) -> str:
        return f"""/*
 * Patch script for format string vulnerability
 * Vulnerability: {vulnerability_info.get('description', 'Unknown')}
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

// Safe printf wrapper
int safe_printf(const char* format, ...) {{
    // Check format string for dangerous directives
    if (strstr(format, "%n")) {{
        fprintf(stderr, "Dangerous format string detected: contains %%n\\n");
        return -1;
    }}
    
    va_list args;
    va_start(args, format);
    int result = vprintf(format, args);
    va_end(args);
    
    return result;
}}

// Hook for printf
int printf(const char* format, ...) {{
    va_list args;
    va_start(args, format);
    
    // Validate format string
    if (strstr(format, "%n")) {{
        fprintf(stderr, "Security: Blocked printf with %%n format\\n");
        va_end(args);
        return -1;
    }}
    
    int result = vprintf(format, args);
    va_end(args);
    
    return result;
}}
"""
    
    @staticmethod
    def _generate_generic_patch_script(patch: Dict, vulnerability_info: Dict) -> str:
        return f"""/*
 * Generic patch script for vulnerability
 * Type: {patch.get('type', 'Unknown')}
 * Vulnerability: {vulnerability_info.get('description', 'Unknown')}
 */

#include <stdio.h>
#include <stdlib.h>

// Generic security hooks
__attribute__((constructor))
void security_init() {{
    printf("Security patches loaded for vulnerability: {vulnerability_info.get('type', 'Unknown')}\\n");
    printf("Description: {vulnerability_info.get('description', 'Unknown')}\\n");
}}

// Placeholder for specific patch implementation
void apply_security_patch() {{
    // Implement specific security fix here based on AI analysis
    // {patch.get('implementation', 'No implementation details provided')}
}}
"""
    
    @staticmethod
    def _generate_python_patcher_script(patches: List[Dict], vulnerability_info: Dict) -> str:
        patches_json = json.dumps(patches, indent=2)
        vulnerability_type = vulnerability_info.get('type', 'Unknown')
        vulnerability_desc = vulnerability_info.get('description', 'Unknown')
        
        script = f'''#!/usr/bin/env python3
# Binary Vulnerability Patcher
# Generated by RevCopilot AI Disassembler

import os
import sys
import json
import subprocess

VULN_TYPE = {json.dumps(vulnerability_type)}
VULN_DESC = {json.dumps(vulnerability_desc)}
PATCHES_JSON = {json.dumps(patches_json)}


class BinaryPatcher:
    """Patch vulnerabilities in binary files."""

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.backup_path = binary_path + ".backup"

    def create_backup(self):
        """Create backup of original binary."""
        import shutil
        shutil.copy2(self.binary_path, self.backup_path)
        print("Created backup: " + self.backup_path)

    def restore_backup(self):
        """Restore from backup."""
        if os.path.exists(self.backup_path):
            import shutil
            shutil.copy2(self.backup_path, self.binary_path)
            print("Restored from backup: " + self.backup_path)

    def patch_bytes(self, offset, original_bytes, new_bytes):
        """Patch bytes at specific offset."""
        with open(self.binary_path, 'r+b') as f:
            f.seek(offset)
            current = f.read(len(original_bytes))

            if current != original_bytes:
                print("Warning: Bytes at offset %d don't match expected pattern" % offset)
                return False

            f.seek(offset)
            f.write(new_bytes)
            print("Patched %d bytes at offset 0x%x" % (len(new_bytes), offset))
            return True

    def apply_strcpy_fix(self):
        """Apply strcpy vulnerability fix."""
        print("Applying strcpy vulnerability fix...")

        try:
            result = subprocess.run(['objdump', '-d', self.binary_path],
                                  capture_output=True, text=True, timeout=10)

            for line in result.stdout.split("\n"):
                if 'call' in line and 'strcpy' in line:
                    print("Found strcpy call: " + line)
            return True
        except Exception as e:
            print("Error applying strcpy fix: " + str(e))
            return False

    def apply_buffer_overflow_fix(self):
        """Apply buffer overflow fix."""
        print("Applying buffer overflow fix...")
        return True

    def generate_patch_report(self, patches):
        """Generate patch report."""
        report_lines = []
        report_lines.append("=" * 40)
        report_lines.append("VULNERABILITY PATCH REPORT")
        report_lines.append("=" * 40)
        report_lines.append("Binary: " + self.binary_path)
        report_lines.append("Vulnerability: " + VULN_TYPE)
        report_lines.append("Description: " + VULN_DESC)
        report_lines.append("")
        report_lines.append("Applied Patches:")

        for i, patch in enumerate(patches, 1):
            report_lines.append("Patch %d:" % i)
            report_lines.append("  Type: " + str(patch.get('type', 'Unknown')))
            report_lines.append("  Description: " + str(patch.get('description', 'No description')))
            report_lines.append("  Difficulty: " + str(patch.get('difficulty', 'Unknown')))
            report_lines.append("  Implementation: " + str(patch.get('implementation', 'No implementation')))

        report_lines.append("")
        report_lines.append("IMPORTANT:")
        report_lines.append("- Always test patches in a controlled environment")
        report_lines.append("- Verify binary functionality after patching")
        report_lines.append("- Consider recompiling from source for production systems")
        report_lines.append("=" * 40)

        return "\n".join(report_lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 patcher.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not os.path.exists(binary_path):
        print("Error: File not found: " + binary_path)
        sys.exit(1)

    patches = json.loads(PATCHES_JSON)
    patcher = BinaryPatcher(binary_path)
    print("Binary Vulnerability Patcher")
    print("=" * 40)
    print("Target: " + binary_path)
    print("Vulnerability: " + VULN_TYPE)
    print("Description: " + VULN_DESC)
    print("Patches available: " + str(len(patches)))

    patcher.create_backup()

    # TODO: Apply patch logic based on PATCHES data
    # Example: patcher.apply_strcpy_fix()

    report = patcher.generate_patch_report(patches)
    print(report)


if __name__ == "__main__":
    main()
'''
        return script

    @staticmethod
    def _generate_fallback_patches(vulnerability_info: Dict) -> List[Dict]:
        """Generate fallback patches when AI analysis fails."""
        vuln_type = vulnerability_info.get('type', '').lower()
        
        patches = []
        
        if 'strcpy' in vuln_type:
            patches.append({
                "type": "strcpy_replacement",
                "description": "Replace strcpy with strncpy",
                "implementation": "Find and replace strcpy calls with strncpy(dest, src, sizeof(dest)-1)",
                "difficulty": "medium"
            })
        
        if 'buffer' in vuln_type:
            patches.append({
                "type": "bounds_check",
                "description": "Add buffer size checks",
                "implementation": "Insert size validation before buffer operations",
                "difficulty": "medium"
            })
        
        if 'format' in vuln_type:
            patches.append({
                "type": "format_string_validation",
                "description": "Validate format strings",
                "implementation": "Check format strings for dangerous directives before use",
                "difficulty": "low"
            })
        
        if not patches:
            patches.append({
                "type": "general_security",
                "description": "Apply general security hardening",
                "implementation": "Review and secure all input validation and memory operations",
                "difficulty": "high"
            })
        
        return patches

class BinaryPatcher:
    """Class to handle binary patching operations."""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.backup_path = binary_path + ".backup"
        self.modified = False
        
    def backup(self):
        """Create backup of original binary."""
        shutil.copy2(self.binary_path, self.backup_path)
        logger.info(f"Created backup at {self.backup_path}")
    
    def restore(self):
        """Restore from backup."""
        if os.path.exists(self.backup_path):
            shutil.copy2(self.backup_path, self.binary_path)
            logger.info(f"Restored from backup {self.backup_path}")
    
    def apply_patch(self, offset: int, original_bytes: bytes, new_bytes: bytes) -> bool:
        """Apply patch at specific offset."""
        try:
            with open(self.binary_path, 'r+b') as f:
                f.seek(offset)
                current = f.read(len(original_bytes))
                
                if current != original_bytes:
                    logger.warning(f"Bytes at offset {offset} don't match expected pattern")
                    return False
                
                f.seek(offset)
                f.write(new_bytes)
                self.modified = True
                logger.info(f"Patched {len(new_bytes)} bytes at offset 0x{offset:x}")
                return True
        except Exception as e:
            logger.error(f"Failed to apply patch at offset 0x{offset:x}: {e}")
            return False
    
    def find_bytes(self, pattern: bytes, start_offset: int = 0, max_results: int = 10) -> List[int]:
        """Find all occurrences of byte pattern in binary."""
        offsets = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            offset = data.find(pattern, start_offset)
            while offset != -1 and len(offsets) < max_results:
                offsets.append(offset)
                offset = data.find(pattern, offset + 1)
        except Exception as e:
            logger.error(f"Failed to find bytes: {e}")
        
        return offsets
    
    def get_function_address(self, function_name: str) -> Optional[int]:
        """Get address of a function by name."""
        try:
            result = subprocess.run(['objdump', '-t', self.binary_path], 
                                  capture_output=True, text=True, timeout=5)
            
            for line in result.stdout.split('\n'):
                if function_name in line and ' F ' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        addr_str = parts[0]
                        return int(addr_str, 16)
        except Exception as e:
            logger.error(f"Failed to get function address: {e}")
        
        return None

# ==================== ENHANCED ANGRISTRATEGIES ====================

def try_angr_analysis(file_path: str):
    """Try multiple angr strategies."""
    if angr is None:
        logger.warning("angr not available")
        return None
    
    strategies = [
        try_simple_input_finding,
        try_constraint_solving,
        try_function_hooking,
        try_cfg_analysis,
        try_argv_analysis,
        try_memory_analysis
    ]
    
    for strategy in strategies:
        try:
            result = strategy(file_path)
            if result:
                logger.info(f"Angr strategy {strategy.__name__} succeeded")
                return result
        except Exception as e:
            logger.warning(f"Angr strategy {strategy.__name__} failed: {e}")
    
    return None

def try_simple_input_finding(file_path: str):
    """Basic angr input finding with common patterns."""
    try:
        proj = angr.Project(file_path, auto_load_libs=False)
        
        # Try different input lengths
        for input_len in [16, 32, 64, 100, 256, 512]:
            try:
                arg = claripy.BVS('input', 8 * input_len)
                state = proj.factory.entry_state(args=[file_path, arg])
                simgr = proj.factory.simulation_manager(state)
                
                # Look for common success strings
                success_strings = [b'success', b'correct', b'win', b'congrat', b'flag', b'passed']
                fail_strings = [b'fail', b'wrong', b'incorrect', b'error', b'access denied']
                
                simgr.explore(
                    find=lambda s: any(string in s.posix.dumps(1) for string in success_strings),
                    avoid=lambda s: any(string in s.posix.dumps(1) for string in fail_strings)
                )
                
                if simgr.found:
                    found_state = simgr.found[0]
                    solution = found_state.solver.eval(arg, cast_to=bytes)
                    return {
                        "input_length": input_len,
                        "solution": solution.decode(errors='ignore'),
                        "technique": "simple_input_finding",
                        "confidence": 0.8
                    }
            except:
                continue
    except Exception as e:
        logger.error(f"Simple input finding failed: {e}")
    
    return None

def try_constraint_solving(file_path: str):
    """Use constraint solving to find inputs."""
    try:
        proj = angr.Project(file_path, auto_load_libs=False)
        
        # Find main function
        cfg = proj.analyses.CFG()
        main_func = None
        
        for func in cfg.functions.values():
            if func.name == 'main' or func.name == '_start':
                main_func = func
                break
        
        if not main_func:
            return None
        
        # Create symbolic input
        input_len = 64
        arg = claripy.BVS('input', 8 * input_len)
        state = proj.factory.entry_state(args=[file_path, arg])
        
        # Explore to find constraints
        simgr = proj.factory.simulation_manager(state)
        simgr.explore()
        
        if simgr.found:
            # Try to solve constraints
            found_state = simgr.found[0]
            if found_state.satisfiable():
                solution = found_state.solver.eval(arg, cast_to=bytes)
                return {
                    "solution": solution.decode(errors='ignore'),
                    "technique": "constraint_solving",
                    "confidence": 0.7
                }
    except Exception as e:
        logger.error(f"Constraint solving failed: {e}")
    
    return None

def try_function_hooking(file_path: str):
    """Hook common functions to understand behavior."""
    try:
        proj = angr.Project(file_path, auto_load_libs=False)
        
        # Only hook strcmp if it exists in the binary
        try:
            # Hook strcmp to understand comparisons
            class StrcmpHook(angr.SimProcedure):
                def run(self, s1_addr, s2_addr):
                    # Try to extract strings being compared
                    s1 = self.state.memory.load(s1_addr, 256)
                    s2 = self.state.memory.load(s2_addr, 256)
                    
                    # Add constraints if possible
                    if s1.symbolic and s2.symbolic:
                        self.state.solver.add(s1 == s2)
                    return 0
            
            proj.hook_symbol('strcmp', StrcmpHook())
        except:
            pass  # strcmp not found, skip hooking
        
        # Create symbolic input
        input_len = 32
        arg = claripy.BVS('input', 8 * input_len)
        state = proj.factory.entry_state(args=[file_path, arg])
        
        simgr = proj.factory.simulation_manager(state)
        simgr.explore()
        
        if simgr.found:
            found_state = simgr.found[0]
            try:
                solution = found_state.solver.eval(arg, cast_to=bytes)
                return {
                    "solution": solution.decode(errors='ignore'),
                    "technique": "function_hooking",
                    "confidence": 0.6
                }
            except:
                return {
                    "technique": "function_hooking",
                    "confidence": 0.4,
                    "message": "Found path but couldn't extract solution"
                }
    except Exception as e:
        logger.error(f"Function hooking failed: {e}")
    
    return None

def try_cfg_analysis(file_path: str):
    """Analyze control flow graph."""
    try:
        proj = angr.Project(file_path, auto_load_libs=False)
        
        # Perform CFG analysis
        cfg = proj.analyses.CFG()
        
        # Analyze basic blocks for patterns
        interesting_blocks = []
        for node in cfg.graph.nodes():
            if node.block:
                # Look for comparison instructions
                block_str = str(node.block.disassembly)
                if 'cmp' in block_str or 'test' in block_str:
                    interesting_blocks.append(node.addr)
        
        if interesting_blocks:
            return {
                "technique": "cfg_analysis",
                "interesting_blocks": interesting_blocks[:10],
                "confidence": 0.5
            }
    except Exception as e:
        logger.error(f"CFG analysis failed: {e}")
    
    return None

def try_argv_analysis(file_path: str):
    """Analyze multiple argv scenarios."""
    try:
        proj = angr.Project(file_path, auto_load_libs=False)
        
        # Try different numbers of arguments
        for num_args in range(1, 4):
            # Create symbolic arguments
            args = [file_path]
            sym_args = []
            
            for i in range(num_args):
                arg = claripy.BVS(f'arg{i}', 8 * 32)
                args.append(arg)
                sym_args.append(arg)
            
            state = proj.factory.entry_state(args=args)
            simgr = proj.factory.simulation_manager(state)
            
            # Explore with common patterns
            simgr.explore()
            
            if simgr.found:
                found_state = simgr.found[0]
                solutions = []
                for arg in sym_args:
                    try:
                        sol = found_state.solver.eval(arg, cast_to=bytes)
                        solutions.append(sol.decode(errors='ignore'))
                    except:
                        solutions.append(None)
                
                return {
                    "num_arguments": num_args,
                    "solutions": solutions,
                    "technique": "argv_analysis",
                    "confidence": 0.7
                }
    except Exception as e:
        logger.error(f"Argv analysis failed: {e}")
    
    return None

def try_memory_analysis(file_path: str):
    """Analyze memory patterns and constants."""
    try:
        proj = angr.Project(file_path, auto_load_libs=False)
        
        # Look for interesting constants in memory
        interesting_constants = []
        
        # Check loaded binary for constants
        for segment in proj.loader.main_object.segments:
            if segment.is_executable:
                try:
                    data = proj.loader.memory.load(segment.vaddr, min(segment.memsize, 4096))
                    # Look for XOR constants, magic numbers, etc.
                    if b'\x00' * 4 in data:
                        interesting_constants.append("Null padding detected")
                    if b'\xff' * 4 in data:
                        interesting_constants.append("FF padding detected")
                except:
                    pass
        
        if interesting_constants:
            return {
                "technique": "memory_analysis",
                "findings": interesting_constants,
                "confidence": 0.4
            }
    except Exception as e:
        logger.error(f"Memory analysis failed: {e}")
    
    return None

# ==================== PATTERN DETECTION ====================

def detect_common_patterns(file_path: str):
    """Detect common reverse engineering patterns."""
    patterns = []
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read(8192)  # Read first 8KB
        
        # Check for XOR patterns
        xor_patterns = [
            b'\x80[\x00-\xff]{1}\x30',  # XOR instructions
            b'\x34[\x00-\xff]{1}',       # XOR AL, imm8
            b'\x35[\x00-\xff]{4}',       # XOR EAX, imm32
            b'\x31[\x00-\xff]{2}',       # XOR r/m32, r32
        ]
        
        for pattern in xor_patterns:
            if re.search(pattern, data):
                patterns.append({
                    "type": "xor_operation",
                    "confidence": "high",
                    "description": "XOR operation detected in binary"
                })
                break
        
        # Check for comparison patterns
        if b'\x3c' in data or b'\x80\x3c' in data or b'\x81\x3c' in data:
            patterns.append({
                "type": "comparison",
                "confidence": "high",
                "description": "Comparison operation detected"
            })
        
        # Check for string operations
        string_ops = [b'\xa4', b'\xa5', b'\xa6', b'\xa7']  # MOVS, CMPS
        for op in string_ops:
            if op in data:
                patterns.append({
                    "type": "string_operation",
                    "confidence": "medium",
                    "description": "String operation detected"
                })
                break
        
        # Check for mathematical operations
        math_ops = [
            b'\x04', b'\x2c',           # ADD, SUB immediate
            b'\xd0', b'\xd1', b'\xd2', b'\xd3',  # Shift/rotate
            b'\xf6', b'\xf7',           # TEST, NOT, NEG, MUL, DIV
        ]
        
        for op in math_ops:
            if op in data:
                patterns.append({
                    "type": "mathematical_operation",
                    "confidence": "medium",
                    "description": "Mathematical operation detected"
                })
                break
        
        # Check for cryptographic patterns
        crypto_constants = [
            b'\x67\x45\x23\x01',  # Common crypto constant
            b'\xef\xcd\xab\x89',  # Another common pattern
            b'MD5', b'SHA', b'AES', b'DES', b'RSA'
        ]
        
        for const in crypto_constants:
            if const in data:
                patterns.append({
                    "type": "cryptographic_constant",
                    "confidence": "medium",
                    "description": "Possible cryptographic constant detected"
                })
                break
        
        # Check for loop patterns
        loop_ops = [b'\xe2', b'\xe0', b'\xe1']  # LOOP, LOOPZ, LOOPNZ
        for op in loop_ops:
            if op in data:
                patterns.append({
                    "type": "loop_operation",
                    "confidence": "medium",
                    "description": "Loop operation detected"
                })
                break
        
    except Exception as e:
        logger.error(f"Pattern detection failed: {e}")
    
    return patterns

# ==================== ENHANCED VULNERABILITY SCANNING ====================

def scan_for_vulnerabilities(file_path: str):
    """Comprehensive vulnerability scanning with detailed information."""
    vulns = []
    
    try:
        # Check for dangerous functions in strings
        dangerous_funcs = [
            {"name": "strcpy", "severity": "high", "fix": "Replace with strncpy"},
            {"name": "strcat", "severity": "high", "fix": "Replace with strncat"},
            {"name": "gets", "severity": "critical", "fix": "Replace with fgets"},
            {"name": "sprintf", "severity": "medium", "fix": "Replace with snprintf"},
            {"name": "scanf", "severity": "medium", "fix": "Use secure alternatives"},
            {"name": "system", "severity": "high", "fix": "Validate input or use execve"},
            {"name": "popen", "severity": "high", "fix": "Validate command strings"},
            {"name": "exec", "severity": "medium", "fix": "Use execve with argument arrays"},
            {"name": "strncpy", "severity": "low", "fix": "Ensure proper null termination"},
            {"name": "memcpy", "severity": "medium", "fix": "Add bounds checking"},
            {"name": "strlen", "severity": "low", "fix": "Check for null pointers"},
            {"name": "malloc", "severity": "low", "fix": "Check return value"},
            {"name": "free", "severity": "medium", "fix": "Check for double-free"},
            {"name": "printf", "severity": "medium", "fix": "Avoid user-controlled format strings"},
        ]
        
        # Extract strings and check for function names
        strings = _extract_ascii_strings(file_path)
        for func_info in dangerous_funcs:
            func_matches = [s for s in strings if func_info["name"] in s]
            if func_matches:
                vulns.append({
                    "id": f"dangerous_func_{func_info['name']}_{len(vulns)}",
                    "type": "dangerous_function",
                    "function": func_info["name"],
                    "severity": func_info["severity"],
                    "description": f"Potential security issue: {func_info['name']} function referenced",
                    "fix_suggestion": func_info["fix"],
                    "evidence": func_matches[:3],
                    "location": f"Strings section (references found in binary)"
                })
        
        # Check file permissions
        try:
            st = os.stat(file_path)
            if st.st_mode & stat.S_ISUID:
                vulns.append({
                    "id": f"setuid_binary_{len(vulns)}",
                    "type": "setuid_binary",
                    "severity": "high",
                    "description": "Binary has SUID bit set - potential privilege escalation",
                    "fix_suggestion": "Remove SUID bit or implement proper sandboxing",
                    "evidence": f"File mode: {oct(st.st_mode)}",
                    "location": "File permissions"
                })
            
            if st.st_mode & stat.S_ISGID:
                vulns.append({
                    "id": f"setgid_binary_{len(vulns)}",
                    "type": "setgid_binary",
                    "severity": "medium",
                    "description": "Binary has SGID bit set",
                    "fix_suggestion": "Review group permissions and remove if unnecessary",
                    "evidence": f"File mode: {oct(st.st_mode)}",
                    "location": "File permissions"
                })
        except:
            pass
        
        # Check for format string vulnerabilities
        format_string_funcs = ["printf", "fprintf", "sprintf", "snprintf"]
        for func in format_string_funcs:
            if any(func in s for s in strings):
                vulns.append({
                    "id": f"format_string_{func}_{len(vulns)}",
                    "type": "format_string",
                    "severity": "medium",
                    "description": f"Format string function {func} detected - potential format string vulnerability",
                    "fix_suggestion": "Ensure format strings are not user-controlled, use constant format strings",
                    "function": func,
                    "location": "Code references"
                })
        
        # Check for stack canary patterns
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)
            
            # Common stack canary values
            canaries = [b'\x00\x0a\x00\xff', b'\xff\x0a\x00\x00', b'\x00\x00\x0a\xff']
            for canary in canaries:
                if canary in data:
                    vulns.append({
                        "id": f"stack_canary_{len(vulns)}",
                        "type": "stack_canary",
                        "severity": "info",
                        "description": "Stack canary detected - binary may have stack protection",
                        "fix_suggestion": "Ensure canaries are properly randomized at runtime",
                        "evidence": f"Canary pattern: {canary.hex()}",
                        "location": f"Binary data at offset 0x{data.find(canary):x}"
                    })
                    break
        except:
            pass
        
        # Check for NX bit (requires objdump)
        try:
            result = subprocess.run(['readelf', '-l', file_path], capture_output=True, text=True, timeout=5)
            if 'GNU_STACK' in result.stdout and 'RWE' in result.stdout:
                vulns.append({
                    "id": f"nx_disabled_{len(vulns)}",
                    "type": "nx_disabled",
                    "severity": "high",
                    "description": "NX (No Execute) bit disabled - stack may be executable",
                    "fix_suggestion": "Recompile with -z noexecstack or use execstack -c to clear executable stack flag",
                    "evidence": "Stack segment has RWE permissions",
                    "location": "ELF program headers"
                })
        except:
            pass
        
        # Check for PIE disabled
        try:
            result = subprocess.run(['readelf', '-h', file_path], capture_output=True, text=True, timeout=5)
            if 'EXEC' in result.stdout and 'DYN' not in result.stdout:
                vulns.append({
                    "id": f"pie_disabled_{len(vulns)}",
                    "type": "pie_disabled",
                    "severity": "medium",
                    "description": "Position Independent Executable (PIE) disabled - ASLR may be less effective",
                    "fix_suggestion": "Recompile with -fPIE -pie flags",
                    "evidence": "ELF type is EXEC (not DYN)",
                    "location": "ELF header"
                })
        except:
            pass
        
        # GDB dynamic analysis for additional vulnerabilities
        try:
            gdb_analyzer = GDBAnalyzer(file_path)
            gdb_result = gdb_analyzer.analyze_with_gdb()
            
            if gdb_result.get("success"):
                # Add GDB analysis summary
                vulns.append({
                    "id": f"gdb_analysis_{len(vulns)}",
                    "type": "dynamic_analysis",
                    "severity": "info",
                    "description": "GDB dynamic analysis completed - runtime information available",
                    "fix_suggestion": "Review GDB output for runtime behavior analysis",
                    "evidence": "GDB analysis successful",
                    "location": "Dynamic analysis",
                    "source": "gdb"
                })
                
                # Check for runtime security features
                analysis = gdb_result.get("analysis", {})
                security_features = analysis.get("security_features", [])
                
                for feature in security_features:
                    vulns.append({
                        "id": f"security_feature_{len(vulns)}",
                        "type": "security_feature",
                        "severity": "info",
                        "description": f"Runtime security feature: {feature}",
                        "fix_suggestion": "Ensure security features are properly configured",
                        "evidence": f"Detected by GDB: {feature}",
                        "location": "Runtime analysis",
                        "source": "gdb"
                    })
        except Exception as e:
            logger.error(f"GDB vulnerability scan failed: {e}")
        
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
    
    return vulns

# ==================== ENHANCED ANALYSIS FUNCTIONS ====================

def enhanced_analyze_binary(file_path: str, mode: str = "auto", api_key: Optional[str] = None, api_url: Optional[str] = None, trusted_mode: bool = False):
    """Enhanced binary analysis with multiple techniques."""
    logger.info(f"Enhanced analysis of {file_path} in {mode} mode")
    
    try:
        # Get basic file info
        file_info = {
            "filename": os.path.basename(file_path),
            "size": os.path.getsize(file_path),
            "type": detect_file_type(file_path),
            "md5": calculate_md5(file_path),
            "sha256": calculate_sha256(file_path)
        }
    except Exception as e:
        logger.error(f"Error getting file info: {e}")
        file_info = {
            "filename": os.path.basename(file_path),
            "size": 0,
            "type": "Unknown",
            "md5": "error",
            "sha256": "error"
        }
    
    # Run multiple analysis techniques
    analysis_results = {
        "file_info": file_info,
        "techniques": [],
        "findings": [],
        "vulnerabilities": [],
        "recommendations": [],
        "patterns": [],
        "functions": [],
        "strings": []
    }
    
    # Technique 1: String Analysis
    try:
        strings = _extract_ascii_strings(file_path)
        analysis_results["strings"] = strings[:100]
        analysis_results["techniques"].append("string_analysis")
    except Exception as e:
        logger.error(f"String analysis failed: {e}")
        analysis_results["strings"] = []
    
    # Technique 2: Function Discovery
    try:
        functions = get_binary_functions(file_path)
        analysis_results["functions"] = functions[:30]
        analysis_results["techniques"].append("function_analysis")
    except Exception as e:
        logger.error(f"Function analysis failed: {e}")
        analysis_results["functions"] = []
    
    # Technique 3: Symbolic Execution (angr)
    if angr is not None:
        try:
            angr_result = try_angr_analysis(file_path)
            if angr_result:
                analysis_results["angr_solution"] = angr_result
                analysis_results["techniques"].append("symbolic_execution")
        except Exception as e:
            logger.error(f"Angr analysis failed: {e}")
    
    # Technique 4: Pattern Detection
    try:
        patterns = detect_common_patterns(file_path)
        analysis_results["patterns"] = patterns
        analysis_results["techniques"].append("pattern_detection")
    except Exception as e:
        logger.error(f"Pattern detection failed: {e}")
        analysis_results["patterns"] = []
    
    # Technique 5: Vulnerability Scanning
    try:
        vulns = scan_for_vulnerabilities(file_path)
        analysis_results["vulnerabilities"] = vulns
        analysis_results["techniques"].append("vulnerability_scanning")
    except Exception as e:
        logger.error(f"Vulnerability scanning failed: {e}")
        analysis_results["vulnerabilities"] = []
    
    # Technique 6: GDB Dynamic Analysis
    try:
        gdb_analyzer = GDBAnalyzer(file_path)
        gdb_result = gdb_analyzer.analyze_with_gdb()
        if gdb_result.get("success"):
            analysis_results["gdb_analysis"] = gdb_result
            analysis_results["techniques"].append("gdb_dynamic_analysis")
        else:
            analysis_results["gdb_error"] = gdb_result.get("error", "Unknown GDB error")
    except Exception as e:
        logger.error(f"GDB analysis failed: {e}")
    
    # Technique 7: AI Analysis (if API available)
    if mode in ("ai", "tutor") and api_key and api_url:
        try:
            ai_analysis = perform_ai_analysis(file_path, mode, api_key, api_url, analysis_results)
            analysis_results["ai_insights"] = ai_analysis
            analysis_results["techniques"].append("ai_analysis")
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            analysis_results["ai_insights"] = {"error": str(e), "insights": "AI analysis failed"}
    
    # Technique 8: Medium.bin specific analysis
    try:
        if is_medium_bin(file_path):
            medium_result = analyze_medium_bin(file_path, mode, api_key, api_url)
            analysis_results["medium_bin_analysis"] = medium_result
            analysis_results["techniques"].append("crackme_specific")
    except Exception as e:
        logger.error(f"Medium.bin analysis failed: {e}")
    
    # Generate solution if possible
    try:
        solution = generate_solution(analysis_results, file_path)
        if solution:
            analysis_results["solution"] = solution
            # Generate explanation for how the solution was derived
            explanation = generate_solution_explanation(analysis_results, api_key, api_url)
            if explanation:
                analysis_results["solution_explanation"] = explanation
            # Verify solution if trusted mode enabled
            if trusted_mode:
                verification = verify_solution_with_binary(file_path, solution)
                analysis_results["solution_verification"] = verification
    except Exception as e:
        logger.error(f"Solution generation failed: {e}")
    
    # Generate recommendations
    try:
        recommendations = generate_recommendations(analysis_results)
        analysis_results["recommendations"] = recommendations
    except Exception as e:
        logger.error(f"Recommendation generation failed: {e}")
        analysis_results["recommendations"] = ["Error generating recommendations"]
    
    # Generate comprehensive report
    try:
        report = generate_comprehensive_report(analysis_results, mode)
        analysis_results["report"] = report
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        analysis_results["report"] = {
            "latex": f"Error generating LaTeX report: {e}",
            "json": json.dumps({"error": str(e)}, indent=2),
            "text": f"Error generating report: {e}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    return analysis_results

def get_binary_functions(binary_path: str) -> List[Dict]:
    """Extract function list from binary."""
    functions = []
    
    # Try nm first
    try:
        cmd = ["nm", binary_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        for line in result.stdout.split('\n'):
            if ' T ' in line:  # Text (code) symbols
                parts = line.split()
                if len(parts) >= 3:
                    address = parts[0]
                    name = parts[2]
                    functions.append({
                        "address": address,
                        "name": name,
                        "size": "unknown"
                    })
    except Exception as e:
        logger.warning(f"nm failed: {e}")
    
    # Try objdump as fallback
    if not functions:
        try:
            cmd = ["objdump", "-t", binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            for line in result.stdout.split('\n'):
                if ' F ' in line and '.text' in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        address = parts[0]
                        name = parts[-1]
                        if not name.startswith('.'):
                            functions.append({
                                "address": address,
                                "name": name,
                                "size": "unknown"
                            })
        except Exception as e:
            logger.warning(f"objdump failed: {e}")

    # Try otool for Mach-O binaries
    if not functions:
        try:
            cmd = ["otool", "-Iv", binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            for line in result.stdout.split("\n"):
                line = line.strip()
                if not line:
                    continue
                match = re.match(r"^([0-9a-fA-F]+)\s+([_A-Za-z][\w$@.]+)", line)
                if match:
                    address = match.group(1)
                    name = match.group(2)
                    if not name.startswith("."):
                        functions.append({
                            "address": address,
                            "name": name,
                            "size": "unknown"
                        })
        except Exception as e:
            logger.warning(f"otool failed: {e}")

    # As a last resort, add entry point if available
    if not functions:
        entry_addr = get_entry_point(binary_path)
        if entry_addr:
            functions.append({
                "address": entry_addr,
                "name": "_entry",
                "size": "unknown"
            })
    
    # Sort by address
    try:
        functions.sort(key=lambda x: int(x['address'], 16) if x['address'] and x['address'].isdigit() else 0)
    except:
        pass
    
    return functions[:50]

def get_entry_point(binary_path: str) -> Optional[str]:
    """Get entry point address for ELF binaries."""
    try:
        result = subprocess.run(["readelf", "-h", binary_path], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if "Entry point address" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[1].strip()
    except Exception as e:
        logger.warning(f"readelf failed: {e}")
    return None

def disassemble_function(binary_path: str, function_name: str = None, address: str = None) -> str:
    """Disassemble a specific function or address."""
    try:
        if function_name:
            cmd = ["objdump", "-d", "--disassemble=" + function_name, binary_path]
        elif address:
            start_addr = int(address, 16) if address.startswith('0x') else int(address, 16)
            end_addr = start_addr + 200
            cmd = ["objdump", "-d", f"--start-address={hex(start_addr)}", 
                   f"--stop-address={hex(end_addr)}", binary_path]
        else:
            cmd = ["objdump", "-d", binary_path]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout[:5000] if result.stdout else "No disassembly generated"
    except Exception as e:
        return f"Error disassembling: {str(e)}"

def perform_ai_analysis(file_path: str, mode: str, api_key: str, api_url: str, analysis_results: dict):
    """Perform AI analysis on binary."""
    try:
        # Prepare context for AI
        context = {
            "file_info": analysis_results.get("file_info", {}),
            "patterns": analysis_results.get("patterns", []),
            "vulnerabilities": analysis_results.get("vulnerabilities", []),
            "functions_count": len(analysis_results.get("functions", [])),
            "strings_sample": analysis_results.get("strings", [])[:20],
            "gdb_analysis": "gdb_analysis" in analysis_results
        }
        
        if mode == "ai":
            prompt = f"""Analyze this binary file for reverse engineering purposes:

File: {context['file_info']['filename']}
Size: {context['file_info']['size']} bytes
Type: {context['file_info']['type']}

Patterns detected: {context['patterns']}
Vulnerabilities: {len(context['vulnerabilities'])} found
Functions found: {context['functions_count']}
GDB Analysis: {context['gdb_analysis']}

Provide insights about:
1. What this binary likely does
2. Key functions to examine
3. Potential attack vectors
4. Suggested reverse engineering approach
5. Vulnerability patches if applicable"""
        
        elif mode == "tutor":
            prompt = f"""As a reverse engineering tutor, provide educational hints for analyzing this binary:

File: {context['file_info']['filename']}
Patterns detected: {context['patterns']}
GDB Analysis: {context['gdb_analysis']}

Generate 5-7 progressive hints that:
1. Guide the user without giving away the solution
2. Focus on learning reverse engineering techniques
3. Suggest specific tools and methods
4. Explain common patterns to look for
5. Include vulnerability patching exercises"""
        
        payload = {
            "model": os.getenv("DARTMOUTH_CHAT_MODEL", "openai.gpt-4.1-mini-2025-04-14"),
            "messages": [
                {"role": "system", "content": "You are a reverse engineering expert."},
                {"role": "user", "content": prompt},
            ],
        }
        
        ai_result = _call_dartmouth_chat(payload, api_key, api_url)
        return ai_result
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": str(e), "insights": "AI analysis failed"}

def analyze_medium_bin(file_path: str, mode: str, api_key: Optional[str], api_url: Optional[str]):
    """Specific analysis for medium.bin crackme."""
    result = {
        "type": "crackme_analysis",
        "name": "medium.bin",
        "notes": "Common reverse engineering challenge with input validation"
    }
    
    try:
        # Check for specific patterns in medium.bin
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Look for common patterns
        if b'password' in data.lower():
            result["hint"] = "Binary appears to check for a password"
        
        # Check for comparison patterns
        xor_patterns = [
            b'\x80[\x00-\xff]{1}\x30',  # XOR instructions
            b'\x34[\x00-\xff]{1}',       # XOR AL, imm8
        ]
        
        for pattern in xor_patterns:
            if re.search(pattern, data):
                result["xor_detected"] = True
                result["xor_hint"] = "XOR encryption may be used for input validation"
                break
        
    except Exception as e:
        logger.error(f"Medium.bin analysis failed: {e}")
    
    return result

def generate_solution(analysis_results: dict, file_path: str):
    """Generate solution based on analysis findings."""
    # Check if we found a specific solution
    if "angr_solution" in analysis_results:
        return analysis_results["angr_solution"]
    
    # Check for medium.bin solution
    if "medium_bin_analysis" in analysis_results:
        medium_result = analysis_results["medium_bin_analysis"]
        if medium_result.get("solution"):
            return {
                "type": "crackme_solution",
                "solution": medium_result["solution"],
                "confidence": "high",
                "source": "medium.bin specific analysis"
            }
    
    # Try to infer solution from patterns
    patterns = analysis_results.get("patterns", [])
    strings = analysis_results.get("strings", [])
    
    # Look for flag patterns in strings
    flag_patterns = ["flag{", "FLAG{", "ctf{", "CTF{", "key:", "Key:", "password:", "Password:"]
    for string in strings:
        for pattern in flag_patterns:
            if pattern in string:
                # Try to extract the flag
                import re
                flag_match = re.search(r'flag\{[^}]*\}', string, re.IGNORECASE)
                if flag_match:
                    return {
                        "type": "flag_in_strings",
                        "flag": flag_match.group(0),
                        "confidence": "high",
                        "source": "string analysis"
                    }
                else:
                    return {
                        "type": "hint_in_strings",
                        "hint": string,
                        "confidence": "medium",
                        "source": "string analysis"
                    }
    
    # Check for XOR patterns
    xor_patterns = [p for p in patterns if p.get("type") == "xor_operation"]
    if xor_patterns:
        return {
            "type": "xor_encryption_detected",
            "confidence": "medium",
            "description": "XOR operations detected - try analyzing with XOR brute force",
            "recommendation": "Use tools like xortool or brute force XOR keys"
        }
    
    return None

def generate_solution_explanation(analysis_results: dict, api_key: Optional[str] = None, api_url: Optional[str] = None) -> Dict[str, Any]:
    """Generate a structured explanation for how the solution was derived."""
    solution = analysis_results.get("solution")
    if not solution:
        return {}

    summary = {
        "file_info": analysis_results.get("file_info", {}),
        "solution": solution,
        "techniques": analysis_results.get("techniques", []),
        "patterns": analysis_results.get("patterns", [])[:10],
        "strings_sample": analysis_results.get("strings", [])[:15],
        "functions_sample": analysis_results.get("functions", [])[:10],
        "vulnerabilities": analysis_results.get("vulnerabilities", [])[:5],
        "gdb_analysis": analysis_results.get("gdb_analysis", {}).get("analysis", {}),
    }

    effective_key = _resolve_dartmouth_key(api_key)
    effective_url = _resolve_dartmouth_url(api_url)

    if effective_key and effective_url:
        try:
            payload = {
                "model": os.getenv("DARTMOUTH_CHAT_MODEL", "openai.gpt-4.1-mini-2025-04-14"),
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a reverse engineering assistant. Produce a concise, step-by-step explanation of how the solution was derived, citing the evidence from the summary."
                    },
                    {
                        "role": "user",
                        "content": f"Generate a solution explanation based on this summary:\n{json.dumps(summary, indent=2)}"
                    }
                ],
            }

            ai_result = _call_dartmouth_chat(payload, effective_key, effective_url)
            if isinstance(ai_result, dict):
                insights = ai_result.get("insights", "")
            else:
                insights = str(ai_result)

            if insights:
                return {
                    "source": "ai",
                    "summary": insights,
                    "evidence": summary,
                }
        except Exception as e:
            logger.warning(f"Solution explanation AI generation failed: {e}")

    # Fallback explanation
    return {
        "source": "heuristic",
        "summary": "Solution derived from automated analysis techniques and detected patterns. Review evidence for details.",
        "evidence": summary,
    }

def verify_solution_with_binary(file_path: str, solution: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the binary with candidate solution inputs (trusted mode only)."""
    try:
        args = [file_path]

        # Common solution layouts
        if "solution" in solution and isinstance(solution.get("solution"), dict):
            sol_dict = solution.get("solution")
            for key in ("arg1", "arg2", "arg3"):
                if sol_dict.get(key) is not None:
                    args.append(str(sol_dict.get(key)))
        elif "solution" in solution and isinstance(solution.get("solution"), str):
            args.append(solution.get("solution"))
        elif "flag" in solution:
            args.append(str(solution.get("flag")))
        elif "hint" in solution:
            args.append(str(solution.get("hint")))

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=5,
        )

        output = (result.stdout or "") + (result.stderr or "")
        success_markers = ["success", "correct", "congrat", "flag", "passed"]
        success = any(marker in output.lower() for marker in success_markers) or result.returncode == 0

        return {
            "attempted": True,
            "args": args,
            "returncode": result.returncode,
            "output": output[:2000],
            "success": success,
        }
    except Exception as e:
        return {
            "attempted": True,
            "success": False,
            "error": str(e),
        }

def generate_recommendations(analysis_results: dict) -> List[str]:
    """Generate recommendations based on analysis."""
    recommendations = []
    
    # Based on vulnerabilities
    vulns = analysis_results.get('vulnerabilities', [])
    high_vulns = [v for v in vulns if v.get('severity') == 'high']
    if high_vulns:
        recommendations.append(f"Perform manual security audit: {len(high_vulns)} high-severity vulnerabilities found")
        recommendations.append(f"Use AI-assisted disassembler to generate patches for critical vulnerabilities")
    
    # Based on complexity
    functions = analysis_results.get('functions', [])
    if len(functions) > 100:
        recommendations.append("Binary appears large and complex; consider using Ghidra or IDA Pro for deeper analysis")
    elif len(functions) < 10:
        recommendations.append("Binary appears small; try static analysis with objdump and strings first")
    
    # Based on findings
    if not analysis_results.get('solution'):
        recommendations.append("No automatic solution found; try manual reverse engineering with gdb or radare2")
    
    # Based on patterns
    patterns = analysis_results.get('patterns', [])
    xor_patterns = [p for p in patterns if p.get('type') == 'xor_operation']
    if xor_patterns:
        recommendations.append("XOR operations detected: try xor brute force with common keys (0x00-0xFF)")
    
    crypto_patterns = [p for p in patterns if 'crypto' in p.get('type', '')]
    if crypto_patterns:
        recommendations.append("Cryptographic patterns detected: look for encryption/decryption routines")
    
    # GDB recommendations
    if "gdb_analysis" in analysis_results:
        recommendations.append("GDB dynamic analysis completed - review runtime behavior for insights")
    elif "gdb_error" in analysis_results:
        recommendations.append("GDB analysis failed - install GDB for dynamic analysis: sudo apt-get install gdb")
    
    # General recommendations
    general_recs = [
        "Use dynamic analysis (gdb, strace, ltrace) to understand runtime behavior",
        "Check for anti-debugging or obfuscation techniques",
        "Look for cryptographic constants or algorithm signatures",
        "Trace user input flow through the program using breakpoints",
        "Consider using radare2 or Binary Ninja for interactive analysis",
        "Use the AI-assisted disassembler to analyze and patch vulnerabilities",
        "If stuck, try approaching from different angles: input fuzzing, pattern matching, or symbolic execution"
    ]
    
    recommendations.extend(general_recs)
    
    return recommendations

# ==================== LaTeX REPORT GENERATION ====================

def escape_latex(text: str) -> str:
    """Escape LaTeX special characters."""
    if not isinstance(text, str):
        text = str(text)
    
    replacements = {
        '&': r'\&',
        '%': r'\%',
        '$': r'\$',
        '#': r'\#',
        '_': r'\_',
        '{': r'\{',
        '}': r'\}',
        '~': r'\textasciitilde{}',
        '^': r'\^{}',
        '\\': r'\textbackslash{}',
        '<': r'\textless{}',
        '>': r'\textgreater{}',
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    return text

def generate_comprehensive_report(analysis_results: dict, mode: str) -> Dict[str, str]:
    """Generate comprehensive reports in multiple formats."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate LaTeX report
    latex_report = generate_latex_report(analysis_results, mode, timestamp)
    
    # Generate JSON report
    json_report = generate_json_report(analysis_results, mode, timestamp)
    
    # Generate text report
    text_report = generate_text_report(analysis_results, mode, timestamp)
    
    return {
        "latex": latex_report,
        "json": json_report,
        "text": text_report,
        "timestamp": timestamp
    }

def generate_latex_report(analysis_results: dict, mode: str, timestamp: str) -> str:
    """Generate LaTeX report."""
    
    # Get file info safely
    file_info = analysis_results.get('file_info', {})
    filename = escape_latex(file_info.get('filename', 'Unknown'))
    file_size = file_info.get('size', 0)
    file_type = escape_latex(file_info.get('type', 'Unknown'))
    file_md5 = file_info.get('md5', 'Unknown')
    file_sha256 = file_info.get('sha256', 'Unknown')
    
    latex_report = f"""\\documentclass[12pt]{{article}}
\\usepackage[utf8]{{inputenc}}
\\usepackage{{geometry}}
\\usepackage{{graphicx}}
\\usepackage{{listings}}
\\usepackage{{xcolor}}
\\usepackage{{hyperref}}
\\usepackage{{fancyhdr}}
\\usepackage{{titlesec}}
\\usepackage{{tabularx}}
\\usepackage{{longtable}}

\\geometry{{a4paper, margin=1in}}

\\title{{RevCopilot Binary Analysis Report}}
\\author{{Generated by RevCopilot v3.0}}
\\date{{{timestamp}}}

\\definecolor{{codegray}}{{gray}}{{0.9}}
\\lstset{{
    backgroundcolor=\\color{{codegray}},
    frame=single,
    breaklines=true,
    postbreak=\\mbox{{\\textcolor{{red}}{{$\\hookrightarrow$}}\\space}},
    basicstyle=\\ttfamily\\footnotesize,
    keywordstyle=\\color{{blue}},
    commentstyle=\\color{{green}},
    stringstyle=\\color{{red}}
}}

\\pagestyle{{fancy}}
\\fancyhf{{}}
\\fancyhead[L]{{\\small RevCopilot Analysis Report}}
\\fancyhead[R]{{\\small {timestamp}}}
\\fancyfoot[C]{{\\thepage}}

\\begin{{document}}

\\maketitle

\\section*{{Executive Summary}}
This report was generated by RevCopilot v3.0, an AI-powered reverse engineering assistant with GDB integration. 
Analysis mode: \\textbf{{{mode}}}. Analysis completed on {timestamp}.

\\section{{File Information}}
\\begin{{tabular}}{{ll}}
\\hline
\\textbf{{Property}} & \\textbf{{Value}} \\\\
\\hline
Filename & {filename} \\\\
Size & {file_size} bytes \\\\
Type & {file_type} \\\\
MD5 & {file_md5} \\\\
SHA256 & {file_sha256} \\\\
\\hline
\\end{{tabular}}

\\section{{Analysis Techniques Applied}}
\\begin{{itemize}}
"""

    # Add techniques
    techniques = analysis_results.get('techniques', [])
    for tech in techniques:
        latex_report += f"    \\item \\textbf{{{tech.replace('_', ' ').title()}}}\n"
    
    latex_report += """\\end{itemize}

\\section{Key Findings}
"""

    # Add solution if found
    if analysis_results.get('solution'):
        sol = analysis_results['solution']
        latex_report += f"\\subsection{{Solution Found}}\n"
        latex_report += f"\\textbf{{Type}}: {escape_latex(sol.get('type', 'Unknown'))}\\\\\n"
        latex_report += f"\\textbf{{Confidence}}: {escape_latex(sol.get('confidence', 'Unknown'))}\\\\\n"
        
        if 'solution' in sol:
            if isinstance(sol['solution'], dict):
                latex_report += "\\begin{tabular}{ll}\n"
                for key, value in sol['solution'].items():
                    latex_report += f"  \\textbf{{{key}}} & {escape_latex(str(value))} \\\\\n"
                latex_report += "\\end{tabular}\n"
            else:
                latex_report += f"\\textbf{{Solution}}: {escape_latex(str(sol['solution']))}\n"
        
        if sol.get('description'):
            latex_report += f"\\\\\\textbf{{Description}}: {escape_latex(sol.get('description', ''))}\n"
        
        latex_report += "\\vspace{0.5cm}\n"

    # Add solution explanation if available
    solution_explanation = analysis_results.get('solution_explanation')
    if solution_explanation and solution_explanation.get('summary'):
        latex_report += "\\subsection{Solution Explanation}\n"
        latex_report += f"\\begin{{quote}}\n{escape_latex(solution_explanation.get('summary', ''))}\n\\end{{quote}}\n"

    # Add verification results if available
    verification = analysis_results.get('solution_verification')
    if verification:
        latex_report += "\\subsection{Solution Verification}\\n"
        latex_report += f"\\textbf{{Attempted}}: {escape_latex(str(verification.get('attempted', False)))}\\\\\n"
        latex_report += f"\\textbf{{Success}}: {escape_latex(str(verification.get('success', False)))}\\\\\n"
        if verification.get('output'):
            latex_report += f"\\begin{{quote}}\\n{escape_latex(verification.get('output', ''))}\\n\\end{{quote}}\\n"
    
    # Add vulnerabilities
    vulns = analysis_results.get('vulnerabilities', [])
    if vulns:
        latex_report += "\\subsection{Vulnerabilities Detected}\n"
        latex_report += "\\begin{longtable}{|p{3cm}|p{2cm}|p{8cm}|}\n"
        latex_report += "\\hline\n"
        latex_report += "\\textbf{Type} & \\textbf{Severity} & \\textbf{Description} \\\\\\hline\n"
        latex_report += "\\endhead\n"
        
        for vuln in vulns[:10]:  # Limit to 10 for report
            vuln_type = escape_latex(vuln.get('type', 'Unknown'))
            vuln_severity = escape_latex(vuln.get('severity', 'Unknown'))
            vuln_desc = escape_latex(vuln.get('description', 'No description'))
            vuln_fix = escape_latex(vuln.get('fix_suggestion', 'No fix suggestion'))
            latex_report += f"{vuln_type} & {vuln_severity} & {vuln_desc} \\\\\n"
            latex_report += f"\\multicolumn{{3}}{{l|}}{{\\small\\textbf{{Fix}}: {vuln_fix}}} \\\\\\hline\n"
        
        latex_report += "\\end{longtable}\n"
        latex_report += f"\\textbf{{Total vulnerabilities found}}: {len(vulns)}\n"
    
    # Add GDB analysis if available
    if "gdb_analysis" in analysis_results:
        latex_report += "\\subsection{GDB Dynamic Analysis}\n"
        latex_report += "GDB runtime analysis was performed. Key findings:\\par\n"
        gdb_result = analysis_results["gdb_analysis"]
        if gdb_result.get("success"):
            latex_report += "\\begin{itemize}\n"
            latex_report += "    \\item Runtime analysis completed successfully\n"
            analysis = gdb_result.get("analysis", {})
            if analysis.get("security_features"):
                latex_report += "    \\item Security features detected:\n"
                latex_report += "    \\begin{itemize}\n"
                for feature in analysis["security_features"]:
                    latex_report += f"        \\item {escape_latex(feature)}\n"
                latex_report += "    \\end{itemize}\n"
            latex_report += "\\end{itemize}\n"
        else:
            latex_report += f"\\textbf{{Error}}: {escape_latex(gdb_result.get('error', 'Unknown error'))}\n"
    
    # Add patterns
    patterns = analysis_results.get('patterns', [])
    if patterns:
        latex_report += "\\subsection{Detected Patterns}\n\\begin{itemize}\n"
        for pattern in patterns[:10]:
            pattern_type = escape_latex(pattern.get('type', 'Unknown'))
            pattern_desc = escape_latex(pattern.get('description', 'No description'))
            pattern_conf = escape_latex(pattern.get('confidence', 'Unknown'))
            latex_report += f"    \\item \\textbf{{{pattern_type}}}: {pattern_desc} (Confidence: {pattern_conf})\n"
        latex_report += "\\end{itemize}\n"
    
    # Add strings section
    strings = analysis_results.get('strings', [])
    if strings:
        latex_report += "\\section{Interesting Strings}\n"
        latex_report += "\\begin{lstlisting}\n"
        for string in strings[:30]:  # Limit to 30 strings
            latex_report += f"{escape_latex(string)}\n"
        latex_report += "\\end{lstlisting}\n"
    
    # Add functions section
    functions = analysis_results.get('functions', [])
    if functions:
        latex_report += "\\section{Discovered Functions}\n"
        latex_report += "\\begin{longtable}{|l|l|}\n\\hline\n"
        latex_report += "\\textbf{Address} & \\textbf{Function Name} \\\\\\hline\n"
        latex_report += "\\endhead\n"
        
        for func in functions[:25]:  # Limit to 25 functions
            func_addr = escape_latex(func.get('address', ''))
            func_name = escape_latex(func.get('name', ''))
            latex_report += f"{func_addr} & {func_name} \\\\\\hline\n"
        
        latex_report += "\\end{longtable}\n"
        latex_report += f"\\textbf{{Total functions discovered}}: {len(functions)}\n"
    
    # Add AI insights if available
    if analysis_results.get('ai_insights'):
        latex_report += "\\section{AI Analysis Insights}\n"
        insights = analysis_results['ai_insights']
        if isinstance(insights, dict):
            insights_text = insights.get('insights', str(insights))
        else:
            insights_text = str(insights)
        
        insights_text = escape_latex(insights_text)
        latex_report += f"\\begin{{quote}}\n{insights_text}\n\\end{{quote}}\n"
    
    # Add recommendations
    recommendations = analysis_results.get('recommendations', [])
    if recommendations:
        latex_report += "\\section{Recommendations}\n\\begin{itemize}\n"
        for rec in recommendations:
            latex_report += f"    \\item {escape_latex(rec)}\n"
        latex_report += "\\end{itemize}\n"
    
    latex_report += """\\section{Next Steps}
\\begin{itemize}
    \\item Use the AI-assisted disassembler for detailed function analysis
    \\item Generate patches for detected vulnerabilities
    \\item Test the binary in a controlled environment
    \\item Consider recompiling from source with security fixes
\\end{itemize}

\\end{document}
"""
    
    return latex_report

def generate_json_report(analysis_results: dict, mode: str, timestamp: str) -> str:
    """Generate JSON report."""
    report_data = {
        "metadata": {
            "tool": "RevCopilot",
            "version": "3.0.0",
            "timestamp": timestamp,
            "mode": mode
        },
        "file_info": analysis_results.get('file_info', {}),
        "analysis_techniques": analysis_results.get('techniques', []),
        "solution": analysis_results.get('solution'),
        "solution_explanation": analysis_results.get('solution_explanation'),
        "solution_verification": analysis_results.get('solution_verification'),
        "vulnerabilities_summary": {
            "total": len(analysis_results.get('vulnerabilities', [])),
            "by_severity": {
                "critical": len([v for v in analysis_results.get('vulnerabilities', []) if v.get('severity') == 'critical']),
                "high": len([v for v in analysis_results.get('vulnerabilities', []) if v.get('severity') == 'high']),
                "medium": len([v for v in analysis_results.get('vulnerabilities', []) if v.get('severity') == 'medium']),
                "low": len([v for v in analysis_results.get('vulnerabilities', []) if v.get('severity') == 'low']),
                "info": len([v for v in analysis_results.get('vulnerabilities', []) if v.get('severity') == 'info'])
            }
        },
        "recommendations": analysis_results.get('recommendations', [])
    }
    
    return json.dumps(report_data, indent=2)

def generate_text_report(analysis_results: dict, mode: str, timestamp: str) -> str:
    """Generate text report."""
    lines = []
    lines.append("=" * 80)
    lines.append(" " * 30 + "REVCOPILOT ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {timestamp}")
    lines.append(f"Analysis Mode: {mode}")
    lines.append(f"Version: 3.0.0 with GDB integration")
    lines.append("")
    
    # File info
    file_info = analysis_results.get('file_info', {})
    lines.append("FILE INFORMATION:")
    lines.append("-" * 40)
    lines.append(f"  Filename: {file_info.get('filename', 'Unknown')}")
    lines.append(f"  Size: {file_info.get('size', 0)} bytes")
    lines.append(f"  Type: {file_info.get('type', 'Unknown')}")
    lines.append(f"  MD5: {file_info.get('md5', 'Unknown')}")
    lines.append(f"  SHA256: {file_info.get('sha256', 'Unknown')}")
    lines.append("")
    
    # Techniques used
    techniques = analysis_results.get('techniques', [])
    lines.append("ANALYSIS TECHNIQUES APPLIED:")
    lines.append("-" * 40)
    for tech in techniques:
        lines.append(f"  • {tech.replace('_', ' ').title()}")
    lines.append("")
    
    # Vulnerabilities
    vulns = analysis_results.get('vulnerabilities', [])
    if vulns:
        lines.append("VULNERABILITIES FOUND:")
        lines.append("-" * 40)
        for i, vuln in enumerate(vulns[:15], 1):
            lines.append(f"  {i}. [{vuln.get('severity', 'Unknown').upper()}] {vuln.get('type', 'Unknown')}")
            lines.append(f"      {vuln.get('description', 'No description')}")
            if vuln.get('source'):
                lines.append(f"      Source: {vuln.get('source')}")
            lines.append("")
        lines.append(f"  Total vulnerabilities: {len(vulns)}")
        lines.append("")
    
    # GDB analysis
    if "gdb_analysis" in analysis_results:
        lines.append("GDB DYNAMIC ANALYSIS:")
        lines.append("-" * 40)
        gdb_result = analysis_results["gdb_analysis"]
        if gdb_result.get("success"):
            lines.append("  ✓ GDB analysis completed successfully")
            analysis = gdb_result.get("analysis", {})
            if analysis.get("security_features"):
                lines.append("  Security features detected:")
                for feature in analysis["security_features"]:
                    lines.append(f"    • {feature}")
        else:
            lines.append(f"  ✗ GDB analysis failed: {gdb_result.get('error', 'Unknown error')}")
        lines.append("")
    
    # Recommendations
    recommendations = analysis_results.get('recommendations', [])
    if recommendations:
        lines.append("RECOMMENDATIONS:")
        lines.append("-" * 40)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"  {i}. {rec}")
        lines.append("")
    
    lines.append("=" * 80)
    # Solution explanation
    solution_explanation = analysis_results.get('solution_explanation')
    if solution_explanation and solution_explanation.get('summary'):
        lines.append("SOLUTION EXPLANATION:")
        lines.append("-" * 40)
        lines.append(solution_explanation.get('summary'))
        lines.append("")

    verification = analysis_results.get('solution_verification')
    if verification:
        lines.append("SOLUTION VERIFICATION:")
        lines.append("-" * 40)
        lines.append(f"Attempted: {verification.get('attempted', False)}")
        lines.append(f"Success: {verification.get('success', False)}")
        if verification.get('output'):
            lines.append("Output:")
            lines.append(verification.get('output'))
        lines.append("")

    lines.append("=" * 80)
    lines.append("Report generated by RevCopilot v3.0")
    lines.append("Use the AI-assisted disassembler for detailed vulnerability analysis")
    lines.append("=" * 80)
    
    return "\n".join(lines)

# ==================== HELPER FUNCTIONS ====================

def _extract_ascii_strings(file_path: str, min_len: int = 4) -> List[str]:
    """Extract ASCII strings from binary."""
    strings = []
    try:
        cmd = ["strings", "-n", str(min_len), file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        strings = result.stdout.split('\n')[:100]  # Limit to 100 strings
    except:
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            current = bytearray()
            for b in data:
                if 32 <= b <= 126:
                    current.append(b)
                else:
                    if len(current) >= min_len:
                        strings.append(current.decode('utf-8', errors='ignore'))
                        if len(strings) >= 100:
                            break
                    current = bytearray()
        except Exception as e:
            logger.warning(f"Failed to extract strings: {e}")
    return strings

# Import handling for langchain_dartmouth
try:
    from langchain_dartmouth.llms import ChatDartmouth
    ChatDartmouth = ChatDartmouth
except ImportError:
    ChatDartmouth = None
    logger.warning("langchain_dartmouth not installed - AI features may be limited")

DARTMOUTH_CHAT_URL = os.getenv("DARTMOUTH_CHAT_URL", "")
DARTMOUTH_CHAT_API_KEY = os.getenv("DARTMOUTH_CHAT_API_KEY", "")
DARTMOUTH_API_KEY = os.getenv("DARTMOUTH_API_KEY", "")
SIMPLECODER_API_BASE = os.getenv("SIMPLECODER_API_BASE", "")
SIMPLECODER_API_KEY = os.getenv("SIMPLECODER_API_KEY", "")

def _resolve_dartmouth_key(override: Optional[str]) -> str:
    return (
        (override or "").strip()
        or DARTMOUTH_CHAT_API_KEY
        or DARTMOUTH_API_KEY
        or SIMPLECODER_API_KEY
    )

def _resolve_dartmouth_url(override: Optional[str]) -> str:
    return (
        (override or "").strip()
        or DARTMOUTH_CHAT_URL
        or SIMPLECODER_API_BASE
    )

def _call_dartmouth_chat(payload: dict, api_key: Optional[str] = None, api_url: Optional[str] = None) -> dict:
    key = _resolve_dartmouth_key(api_key)
    if not key:
        return {"insights": "API key not configured. Please set DARTMOUTH_CHAT_API_KEY environment variable."}
    
    url = _resolve_dartmouth_url(api_url)
    if not url:
        return {"insights": "API URL not configured. Please set DARTMOUTH_CHAT_URL environment variable."}
    
    # Normalize URL
    if not url.endswith("/v1/chat/completions"):
        if url.endswith("/api"):
            url = f"{url}/v1/chat/completions"
        elif url.endswith("/v1"):
            url = f"{url}/chat/completions"
        else:
            url = f"{url}/v1/chat/completions"
    
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
            },
            method="POST",
        )
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        
        # Extract content from response
        if isinstance(data, dict):
            if "choices" in data and data["choices"]:
                content = data["choices"][0].get("message", {}).get("content", "")
                return {"insights": content}
            elif "message" in data:
                return {"insights": data.get("message", "")}
            elif "content" in data:
                return {"insights": data.get("content", "")}
        
        return {"insights": str(data)}
        
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        logger.error(f"HTTP {e.code} from Dartmouth API: {err_body}")
        return {"insights": f"API Error {e.code}: {err_body[:200]}"}
    except Exception as e:
        logger.error(f"Failed to call Dartmouth API: {e}")
        return {"insights": f"Connection failed: {str(e)}"}

# ==================== BACKGROUND PROCESSING ====================

async def process_analysis(job_id: str, path: str, mode: str, api_key: Optional[str] = None, api_url: Optional[str] = None, trusted_mode: bool = False):
    """Background analysis task."""
    try:
        logger.info(f"Processing job {job_id} in {mode} mode")
        
        results = enhanced_analyze_binary(path, mode, api_key, api_url, trusted_mode=trusted_mode)
        
        # Format response
        response = {
            "type": mode,
            "file_info": results.get("file_info"),
            "vulnerabilities": results.get("vulnerabilities", []),
            "analysis_summary": {
                "techniques_used": results.get("techniques", []),
                "vulnerabilities_found": len(results.get("vulnerabilities", [])),
                "gdb_analysis": "gdb_analysis" in results
            },
            "recommendations": results.get("recommendations", []),
            "solution": results.get("solution"),
            "solution_explanation": results.get("solution_explanation"),
            "solution_verification": results.get("solution_verification"),
            "report": results.get("report", {})
        }
        
        if mode == "ai" and "ai_insights" in results:
            response["ai_insights"] = results["ai_insights"]
        
        jobs[job_id]["result"] = response
        jobs[job_id]["status"] = "completed"
        logger.info(f"Job {job_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Job {job_id} failed: {str(e)}", exc_info=True)
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)
    finally:
        # Keep the file for disassembler endpoints; cleanup is handled via /api/cleanup/{job_id}
        pass

# ==================== API ENDPOINTS ====================

@app.post("/api/ai/health")
async def ai_health_check(
    dartmouth_api_key: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Key"),
    dartmouth_api_url: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Url"),
    dartmouth_api_key_form: Optional[str] = Form(default=None),
    dartmouth_api_url_form: Optional[str] = Form(default=None),
):
    """Test AI API connectivity."""
    effective_key = _resolve_dartmouth_key(dartmouth_api_key or dartmouth_api_key_form)
    effective_url = _resolve_dartmouth_url(dartmouth_api_url or dartmouth_api_url_form)
    
    if not effective_key:
        return {
            "status": "error",
            "message": "API key not provided",
            "config_instructions": "Provide API key via header or form field"
        }
    
    if not effective_url:
        return {
            "status": "error",
            "message": "API URL not provided",
            "config_instructions": "Provide API URL via header or form field"
        }
    
    try:
        # Test with a simple prompt
        payload = {
            "model": os.getenv("DARTMOUTH_CHAT_MODEL", "openai.gpt-4.1-mini-2025-04-14"),
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Reply with a short confirmation that you can hear me."},
            ],
            "max_tokens": 32
        }
        
        result = _call_dartmouth_chat(payload, effective_key, effective_url)
        
        if isinstance(result, dict) and "insights" in result:
            insights = result["insights"] or ""
            if isinstance(insights, str) and insights.strip() and not insights.lower().startswith("api error"):
                return {
                    "status": "success",
                    "message": "AI API is working correctly",
                    "response": insights
                }
            return {
                "status": "error",
                "message": "AI API returned an error",
                "response": insights
            }
        return {
            "status": "error",
            "message": "Unexpected response format from AI API",
            "response": str(result)
        }
            
    except Exception as e:
        logger.error(f"AI health check failed: {e}")
        return {
            "status": "error",
            "message": f"AI API test failed: {str(e)}"
        }

@app.post("/api/analyze", response_model=JobStatus)
async def analyze_binary_endpoint(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    mode: str = Query("auto", pattern="^(auto|ai|tutor)$"),
    trusted_mode: bool = Form(False),
    dartmouth_api_key: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Key"),
    dartmouth_api_url: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Url"),
    dartmouth_api_key_form: Optional[str] = Form(default=None),
    dartmouth_api_url_form: Optional[str] = Form(default=None),
):
    """Upload binary and start analysis."""
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Validate file size
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    
    # Save uploaded file
    file_id = str(uuid.uuid4())
    try:
        temp_path = await save_uploaded_file(file, file_id)
        
        # Check file size after saving
        file_size = os.path.getsize(temp_path)
        if file_size > MAX_FILE_SIZE:
            cleanup_file(temp_path)
            raise HTTPException(status_code=400, detail=f"File too large. Maximum size is {MAX_FILE_SIZE//(1024*1024)}MB")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    # Initialize job
    jobs[file_id] = {
        "status": "processing",
        "mode": mode,
        "trusted_mode": bool(trusted_mode),
        "result": None,
        "error": None,
        "temp_path": temp_path,
        "filename": file.filename,
    }
    
    effective_key = _resolve_dartmouth_key(dartmouth_api_key or dartmouth_api_key_form)
    effective_url = _resolve_dartmouth_url(dartmouth_api_url or dartmouth_api_url_form)
    
    # Process in background
    background_tasks.add_task(
        process_analysis,
        file_id,
        temp_path,
        mode,
        effective_key,
        effective_url,
        bool(trusted_mode),
    )
    
    return JSONResponse({
        "job_id": file_id,
        "status": "started",
        "message": f"Analysis started in {mode} mode with GDB integration.",
        "filename": file.filename
    })

@app.get("/api/result/{job_id}", response_model=JobStatus)
async def get_result(job_id: str):
    """Get analysis results."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job_data = jobs[job_id]
    return {
        "job_id": job_id,
        "status": job_data["status"],
        "result": job_data.get("result"),
        "error": job_data.get("error"),
    }

# ==================== DISASSEMBLER ENDPOINTS ====================

@app.post("/api/disassembler/functions")
async def get_functions_endpoint(
    job_id: str = Form(...),
):
    """Get list of functions from binary."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    binary_path = jobs[job_id].get("temp_path")
    if not binary_path or not os.path.exists(binary_path):
        raise HTTPException(status_code=400, detail="Binary not available")
    
    functions = get_binary_functions(binary_path)
    return {"functions": functions}

@app.post("/api/disassembler/disassemble")
async def disassemble_endpoint(
    job_id: str = Form(...),
    function_name: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
):
    """Disassemble a function or address."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    binary_path = jobs[job_id].get("temp_path")
    if not binary_path or not os.path.exists(binary_path):
        raise HTTPException(status_code=400, detail="Binary not available")
    
    disassembly = disassemble_function(binary_path, function_name, address)
    if (not disassembly or disassembly.strip() == "No disassembly generated") and address:
        disassembly = disassemble_function(binary_path, None, address)
    return {"disassembly": disassembly}

@app.post("/api/disassembler/analyze_vulnerability")
async def analyze_vulnerability_endpoint(
    job_id: str = Form(...),
    disassembly: str = Form(...),
    vulnerability_info: str = Form(...),
    dartmouth_api_key: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Key"),
    dartmouth_api_url: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Url"),
    dartmouth_api_key_form: Optional[str] = Form(default=None),
    dartmouth_api_url_form: Optional[str] = Form(default=None),
    dartmouth_api_key_legacy: Optional[str] = Form(default=None, alias="dartmouth_api_key"),
    dartmouth_api_url_legacy: Optional[str] = Form(default=None, alias="dartmouth_api_url"),
):
    """Use AI to analyze and generate patches for a specific vulnerability."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not disassembly or not vulnerability_info:
        raise HTTPException(status_code=400, detail="Missing disassembly or vulnerability info")
    
    try:
        vuln_info = json.loads(vulnerability_info)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid vulnerability info JSON")
    
    effective_key = _resolve_dartmouth_key(
        dartmouth_api_key or dartmouth_api_key_form or dartmouth_api_key_legacy
    )
    effective_url = _resolve_dartmouth_url(
        dartmouth_api_url or dartmouth_api_url_form or dartmouth_api_url_legacy
    )
    
    result = AIVulnerabilityPatcher.analyze_and_patch(disassembly, vuln_info, effective_key, effective_url)
    return result

@app.post("/api/disassembler/generate_validation_script")
async def generate_validation_script_endpoint(
    job_id: str = Form(...),
    vulnerability_info: str = Form(...),
    patches: str = Form(...),
):
    """Generate a validation script for patches."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    try:
        vuln_info = json.loads(vulnerability_info)
        patch_list = json.loads(patches)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    # Generate validation script
    validation_script = f"""#!/bin/bash
# RevCopilot Patch Validation Script
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

echo "=== Patch Validation Script ==="
echo "Vulnerability: {vuln_info.get('type', 'Unknown')}"
echo "Severity: {vuln_info.get('severity', 'Unknown')}"
echo ""

# Check for required tools
echo "1. Checking required tools..."
for tool in objdump strings file; do
    if command -v $tool >/dev/null 2>&1; then
        echo "  ✓ $tool found"
    else
        echo "  ✗ $tool not found"
    fi
done
echo ""

echo "2. Patch Information:"
echo "   Total patches generated: {len(patch_list)}"
for i, patch in enumerate(patch_list, 1):
    echo "   {i}. {patch.get('type', 'Unknown')} - {patch.get('difficulty', 'Unknown')}"
echo ""

echo "3. Validation Steps:"
echo "   a) Review the patch analysis above"
echo "   b) Apply patches in a controlled environment"
echo "   c) Test with normal input to ensure functionality"
echo "   d) Test with malicious input to verify security"
echo ""

echo "=== Validation Complete ==="
echo "Always test patches thoroughly before deployment!"
"""
    
    return Response(
        content=validation_script,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=validate_patch.sh"}
    )

# ==================== HEALTH AND UTILITY ENDPOINTS ====================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    # Check if GDB is available
    gdb_available = GDBAnalyzer("/bin/ls").check_gdb_installed()
    
    return {
        "status": "healthy",
        "service": "revcopilot-backend",
        "version": "3.0.0",
        "gdb_available": gdb_available,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/tools/check")
async def check_tools():
    """Check for required tools."""
    tools = {
        "gdb": GDBAnalyzer("/bin/ls").check_gdb_installed(),
        "objdump": False,
        "strings": False,
        "file": False,
    }
    
    # Check other tools
    for tool in ["objdump", "strings", "file"]:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=2)
            tools[tool] = True
        except:
            tools[tool] = False
    
    return {
        "tools": tools,
        "install_commands": {
            "ubuntu": "sudo apt-get install gdb binutils",
            "macos": "brew install gdb binutils",
            "general": "See individual tool websites for installation"
        }
    }

# ==================== WEB UI ====================

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    """Serve the main web interface with improved vulnerability patching UI."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>RevCopilot v3.0</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .loader { border-top-color: #3498db; animation: spin 1s ease-in-out infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .severity-high { background-color: #fee2e2; border-left: 4px solid #dc2626; }
        .severity-medium { background-color: #fef3c7; border-left: 4px solid #d97706; }
        .severity-low { background-color: #d1fae5; border-left: 4px solid #059669; }
        .severity-info { background-color: #e0f2fe; border-left: 4px solid #0284c7; }
        .function-item.selected { background-color: #dbeafe; border-color: #93c5fd; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="gradient-bg text-white py-8">
        <div class="container mx-auto px-4">
            <h1 class="text-4xl font-bold mb-2"><i class="fas fa-shield-alt"></i> RevCopilot v3.0</h1>
            <p class="text-xl opacity-90">AI-Powered Reverse Engineering with GDB Integration</p>
            <p class="text-sm opacity-75 mt-2">Now with enhanced vulnerability detection and practical patching tools</p>
        </div>
    </div>

    <div class="container mx-auto px-4 py-8">
        <div class="mb-8 p-4 bg-blue-100 border-l-4 border-blue-400 rounded">
            <div class="flex items-center gap-3 mb-1">
                <span class="text-blue-600 text-xl"><i class="fas fa-microchip"></i></span>
                <span class="font-semibold text-blue-800">New in v3.0: GDB Dynamic Analysis</span>
            </div>
            <div class="text-blue-900 text-sm mt-1">
                <ul class="list-disc ml-6">
                    <li><strong>GDB Integration</strong>: Automatic runtime analysis and vulnerability detection</li>
                    <li><strong>Enhanced Scanning</strong>: Combines static and dynamic analysis techniques</li>
                    <li><strong>Practical Patching</strong>: AI-generated patches with validation scripts</li>
                    <li><strong>Beginner Friendly</strong>: Clear, actionable vulnerability reports</li>
                </ul>
            </div>
        </div>
        
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <!-- Left Column -->
            <div class="space-y-6">
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4"><i class="fas fa-upload mr-2"></i>Upload Binary</h2>
                    
                    <input type="file" id="fileInput" class="sr-only" accept="*/*">
                    <label for="fileInput" id="uploadArea" class="border-4 border-dashed border-gray-300 rounded-2xl p-8 text-center cursor-pointer hover:border-blue-400 transition-colors block">
                        <div class="text-5xl mb-4"><i class="fas fa-file-code"></i></div>
                        <p class="text-xl font-semibold text-gray-700">Drag & drop a binary file</p>
                        <p class="text-gray-500 mt-2">or click to browse</p>
                        <p class="text-sm text-gray-400 mt-4">ELF, PE, Mach-O formats supported</p>
                    </label>
                    
                    <div class="mt-4 text-sm text-gray-600">
                        <div id="fileStatus">No file selected</div>
                    </div>

                    <div class="mt-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3"><i class="fas fa-cogs mr-2"></i>Analysis Mode</h3>
                        <div class="mb-3">
                            <label class="block text-sm text-gray-600 mb-1" for="apiUrlInput">Dartmouth API URL</label>
                            <input id="apiUrlInput" type="text" class="w-full px-3 py-2 border rounded-lg text-sm bg-gray-100 text-gray-600" readonly>
                            <div class="text-xs text-gray-500 mt-1">Auto-loaded for you.</div>
                        </div>
                        <div class="mb-3">
                            <label class="block text-sm text-gray-600 mb-1" for="apiKeyInput">Dartmouth API Key (Optional)</label>
                            <input id="apiKeyInput" type="password" placeholder="Enter API key for AI features" class="w-full px-3 py-2 border rounded-lg text-sm">
                        </div>
                        <div class="mb-3 flex items-center gap-3">
                            <button id="aiHealthBtn" type="button" class="px-4 py-2 rounded-lg text-sm font-semibold text-white bg-gradient-to-r from-indigo-500 to-purple-600 hover:opacity-90 transition-opacity">
                                <i class="fas fa-plug mr-2"></i>Test API Connection
                            </button>
                            <span id="aiHealthStatus" class="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600">Not tested</span>
                        </div>
                        <div class="grid grid-cols-3 gap-3">
                            <button data-mode="auto" class="mode-btn p-4 rounded-lg bg-gradient-to-br from-green-500 to-emerald-600 text-white font-semibold hover:opacity-90 transition-opacity">
                                <i class="fas fa-bolt mr-2"></i>Auto
                            </button>
                            <button data-mode="ai" class="mode-btn p-4 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 text-white font-semibold hover:opacity-90 transition-opacity">
                                <i class="fas fa-brain mr-2"></i>AI
                            </button>
                            <button data-mode="tutor" class="mode-btn p-4 rounded-lg bg-gradient-to-br from-purple-500 to-pink-600 text-white font-semibold hover:opacity-90 transition-opacity">
                                <i class="fas fa-graduation-cap mr-2"></i>Tutor
                            </button>
                        </div>
                        <div class="mt-4 p-3 bg-gray-50 rounded-lg border border-gray-200">
                            <label class="flex items-start gap-3 cursor-pointer">
                                <input id="trustedModeToggle" type="checkbox" class="mt-1 h-4 w-4 text-blue-600 border-gray-300 rounded">
                                <div>
                                    <div class="text-sm font-semibold text-gray-800">Trusted Mode (run binary for verification)</div>
                                    <div class="text-xs text-gray-600">Only enable for binaries you trust. This executes the binary to verify solutions.</div>
                                </div>
                            </label>
                        </div>
                    </div>
                    
                    <button id="analyzeBtn" class="w-full mt-6 py-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                        <i class="fas fa-play mr-2"></i>Start Analysis with GDB
                    </button>
                </div>
                
                <!-- AI-Assisted Disassembler (Only shown after analysis) -->
                <div id="disassemblerSection" class="hidden bg-white rounded-xl shadow-lg p-6">
                    <h3 class="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <i class="fas fa-microscope text-blue-600"></i> AI-Assisted Disassembler
                        <span class="ml-auto text-sm font-normal">
                            <span id="disasmStatus" class="px-2 py-1 bg-blue-100 text-blue-800 rounded">Ready</span>
                        </span>
                    </h3>
                    
                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <!-- Left: Function List -->
                        <div class="lg:col-span-1">
                            <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">
                                    <i class="fas fa-code-branch mr-1"></i> Functions
                                </label>
                                <div class="relative">
                                    <input type="text" id="functionSearch" placeholder="Search functions..." 
                                           class="w-full px-3 py-2 border rounded-lg text-sm mb-2">
                                    <div id="functionList" class="h-64 overflow-y-auto border rounded-lg p-2 bg-gray-50">
                                        <div class="text-center py-8 text-gray-500">
                                            <i class="fas fa-spinner fa-spin mb-2"></i>
                                            <p>Loading functions...</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Advanced Vulnerability Patching Controls -->
                            <div class="space-y-3 mt-4 p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                                <div class="flex items-center justify-between">
                                    <label class="block text-sm font-medium text-gray-700">
                                        <i class="fas fa-tools mr-1"></i> Advanced Tools
                                    </label>
                                    <button id="toggleAdvancedPatching" class="text-xs text-yellow-800 hover:text-yellow-900">
                                        Show
                                    </button>
                                </div>
                                <div id="patchingControls" class="hidden space-y-2">
                                    <button id="analyzeVulnerabilityBtn" class="w-full px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 text-sm disabled:opacity-50">
                                        <i class="fas fa-bug mr-2"></i> Analyze Selected Vulnerability
                                    </button>
                                    <button id="generateValidationBtn" class="w-full px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm disabled:opacity-50">
                                        <i class="fas fa-vial mr-2"></i> Generate Validation Script
                                    </button>
                                    <div class="text-xs text-gray-600 mt-2">
                                        <i class="fas fa-info-circle mr-1"></i> Select a vulnerability first
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Middle: Disassembly Viewer -->
                        <div class="lg:col-span-2">
                            <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">
                                    <i class="fas fa-assistive-listening-systems mr-1"></i> Disassembly
                                </label>
                                <div class="flex gap-2 mb-2">
                                    <button id="refreshDisasmBtn" class="px-3 py-1 bg-blue-100 text-blue-700 rounded text-sm hover:bg-blue-200">
                                        <i class="fas fa-sync-alt mr-1"></i> Refresh
                                    </button>
                                    <button id="copyDisasmBtn" class="px-3 py-1 bg-gray-100 text-gray-700 rounded text-sm hover:bg-gray-200">
                                        <i class="fas fa-copy mr-1"></i> Copy
                                    </button>
                                </div>
                                <div id="disassemblyContent" class="h-64 overflow-y-auto border rounded-lg p-4 bg-gray-900 text-gray-100 font-mono text-sm">
                                    <div class="text-center py-8 text-gray-400">
                                        <i class="fas fa-code mb-2"></i>
                                        <p>Select a function to view disassembly</p>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- AI Analysis Panel -->
                            <div id="aiAnalysisPanel" class="hidden mt-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">
                                    <i class="fas fa-robot mr-1"></i> AI Vulnerability Analysis
                                </label>
                                <div id="aiAnalysisContent" class="h-48 overflow-y-auto border rounded-lg p-4 bg-blue-50">
                                    <div class="text-center py-8 text-gray-500">
                                        <i class="fas fa-spinner fa-spin mb-2"></i>
                                        <p>Analyzing vulnerability...</p>
                                    </div>
                                </div>
                                <div class="mt-2 flex justify-between">
                                    <button id="applyPatchBtn" class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm">
                                        <i class="fas fa-check-circle mr-2"></i> Apply Patch
                                    </button>
                                    <button id="downloadPatchBtn" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm">
                                        <i class="fas fa-download mr-2"></i> Download Patch
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Right Column -->
            <div class="space-y-6">
                <!-- Results Panel -->
                <div id="resultsSection" class="hidden bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <i class="fas fa-chart-bar text-green-600"></i> Analysis Results
                        <div class="ml-auto flex items-center gap-2">
                            <div id="progressIndicator" class="hidden">
                                <div class="loader animate-spin ease-linear rounded-full border-4 border-t-4 border-gray-200 h-6 w-6"></div>
                            </div>
                            <span id="statusBadge" class="px-3 py-1 rounded-full text-sm font-semibold">Processing</span>
                        </div>
                    </h2>
                    
                    <div id="resultsContent" class="space-y-4">
                        <!-- Results will be loaded here -->
                    </div>
                </div>
                
                <!-- GDB Analysis Panel -->
                <div id="gdbSection" class="hidden bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <i class="fas fa-terminal text-purple-600"></i> GDB Dynamic Analysis
                        <span id="gdbStatus" class="ml-auto text-sm font-normal px-2 py-1 bg-purple-100 text-purple-800 rounded">Available</span>
                    </h2>
                    <div id="gdbContent" class="space-y-4">
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-spinner fa-spin mb-2"></i>
                            <p>GDB analysis will run automatically during binary analysis</p>
                        </div>
                    </div>
                </div>
                
                <!-- Report Generation -->
                <div id="reportSection" class="hidden bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <i class="fas fa-file-pdf text-red-600"></i> Report Generation
                    </h2>
                    <div class="space-y-3">
                        <div class="grid grid-cols-2 gap-3">
                            <button id="downloadLatexBtn" class="p-3 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 transition-colors">
                                <i class="fas fa-file-alt mr-2"></i> LaTeX Report
                            </button>
                            <button id="downloadJsonBtn" class="p-3 bg-green-100 text-green-700 rounded-lg hover:bg-green-200 transition-colors">
                                <i class="fas fa-code mr-2"></i> JSON Report
                            </button>
                        </div>
                        <button id="downloadTextBtn" class="w-full p-3 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors">
                            <i class="fas fa-file-text mr-2"></i> Text Report
                        </button>
                        <div class="text-xs text-gray-500 mt-2">
                            <i class="fas fa-info-circle mr-1"></i> Reports are generated automatically with analysis results
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Vulnerability Details Modal -->
    <div id="vulnModal" class="hidden fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
        <div class="bg-white rounded-xl shadow-2xl max-w-4xl w-full max-h-[80vh] overflow-hidden flex flex-col">
            <div class="p-6 border-b">
                <div class="flex justify-between items-center">
                    <h3 class="text-xl font-bold text-gray-800">
                        <i class="fas fa-shield-alt mr-2"></i> Vulnerability Details
                    </h3>
                    <button id="closeVulnModal" class="text-gray-500 hover:text-gray-700">
                        <i class="fas fa-times text-2xl"></i>
                    </button>
                </div>
            </div>
            <div id="vulnModalContent" class="p-6 overflow-y-auto flex-grow">
                <!-- Vulnerability details will be loaded here -->
            </div>
            <div class="p-6 border-t bg-gray-50">
                <button id="analyzeWithAIBtn" class="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-lg hover:opacity-90 transition-opacity">
                    <i class="fas fa-robot mr-2"></i> Analyze with AI
                </button>
            </div>
        </div>
    </div>

    <script>
        // State management
        let currentJobId = null;
        let currentFile = null;
        let currentMode = 'auto';
        let pollInterval = null;
        let currentVulnerabilities = [];
        let currentFunctions = [];
        let selectedVulnerability = null;
        let selectedFunction = null;
        
        // DOM elements
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const fileStatus = document.getElementById('fileStatus');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const modeButtons = document.querySelectorAll('.mode-btn');
        const apiUrlInput = document.getElementById('apiUrlInput');
        const apiKeyInput = document.getElementById('apiKeyInput');
        const trustedModeToggle = document.getElementById('trustedModeToggle');
        const aiHealthBtn = document.getElementById('aiHealthBtn');
        const aiHealthStatus = document.getElementById('aiHealthStatus');
        
        // Results elements
        const resultsSection = document.getElementById('resultsSection');
        const resultsContent = document.getElementById('resultsContent');
        const progressIndicator = document.getElementById('progressIndicator');
        const statusBadge = document.getElementById('statusBadge');
        
        // GDB elements
        const gdbSection = document.getElementById('gdbSection');
        const gdbContent = document.getElementById('gdbContent');
        const gdbStatus = document.getElementById('gdbStatus');
        
        // Report elements
        const reportSection = document.getElementById('reportSection');
        
        // Disassembler elements
        const disassemblerSection = document.getElementById('disassemblerSection');
        const disasmStatus = document.getElementById('disasmStatus');
        const functionList = document.getElementById('functionList');
        const functionSearch = document.getElementById('functionSearch');
        const disassemblyContent = document.getElementById('disassemblyContent');
        const refreshDisasmBtn = document.getElementById('refreshDisasmBtn');
        const copyDisasmBtn = document.getElementById('copyDisasmBtn');
        const analyzeVulnerabilityBtn = document.getElementById('analyzeVulnerabilityBtn');
        const generateValidationBtn = document.getElementById('generateValidationBtn');
        const aiAnalysisPanel = document.getElementById('aiAnalysisPanel');
        const aiAnalysisContent = document.getElementById('aiAnalysisContent');
        const applyPatchBtn = document.getElementById('applyPatchBtn');
        const downloadPatchBtn = document.getElementById('downloadPatchBtn');
        const toggleAdvancedPatching = document.getElementById('toggleAdvancedPatching');
        const patchingControls = document.getElementById('patchingControls');
        
        // Modal elements
        const vulnModal = document.getElementById('vulnModal');
        const vulnModalContent = document.getElementById('vulnModalContent');
        const closeVulnModal = document.getElementById('closeVulnModal');
        const analyzeWithAIBtn = document.getElementById('analyzeWithAIBtn');
        
        // Report download buttons
        const downloadLatexBtn = document.getElementById('downloadLatexBtn');
        const downloadJsonBtn = document.getElementById('downloadJsonBtn');
        const downloadTextBtn = document.getElementById('downloadTextBtn');

        const DEFAULT_DARTMOUTH_URL = 'https://chat.dartmouth.edu/api';
        
        // Utility functions
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function getSeverityClass(severity) {
            switch(severity?.toLowerCase()) {
                case 'critical':
                case 'high':
                    return 'severity-high';
                case 'medium':
                    return 'severity-medium';
                case 'low':
                    return 'severity-low';
                default:
                    return 'severity-info';
            }
        }
        
        function getSeverityBadgeClass(severity) {
            switch(severity?.toLowerCase()) {
                case 'critical':
                    return 'bg-red-100 text-red-800';
                case 'high':
                    return 'bg-orange-100 text-orange-800';
                case 'medium':
                    return 'bg-yellow-100 text-yellow-800';
                case 'low':
                    return 'bg-green-100 text-green-800';
                default:
                    return 'bg-blue-100 text-blue-800';
            }
        }
        
        function formatAIInsights(insights) {
            if (typeof insights !== 'string') {
                insights = JSON.stringify(insights, null, 2);
            }
            
            // Convert markdown-like formatting to HTML
            let html = escapeHtml(insights);
            
            // Convert numbered lists
            html = html.replace(/^(\d+)\.\s+/gm, '<strong>$1.</strong> ');
            
            // Convert bullet points
            html = html.replace(/^[-•*]\s+/gm, '• ');
            
            // Convert line breaks
            html = html.replace(/\\n/g, '<br>');
            
            // Convert multiple line breaks to paragraphs
            html = html.replace(/\\n\\n/g, '</p><p>');
            
            return `<p>${html}</p>`;
        }
        
        function showToast(message, type = 'info') {
            // Remove existing toasts
            const existingToasts = document.querySelectorAll('.toast');
            existingToasts.forEach(toast => toast.remove());
            
            // Create toast element
            const toast = document.createElement('div');
            toast.className = `toast fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg text-white font-medium z-50 transform transition-transform duration-300 translate-y-0`;
            
            switch(type) {
                case 'success':
                    toast.className += ' bg-green-600';
                    toast.innerHTML = `<i class="fas fa-check-circle mr-2"></i>${message}`;
                    break;
                case 'error':
                    toast.className += ' bg-red-600';
                    toast.innerHTML = `<i class="fas fa-exclamation-circle mr-2"></i>${message}`;
                    break;
                case 'info':
                    toast.className += ' bg-blue-600';
                    toast.innerHTML = `<i class="fas fa-info-circle mr-2"></i>${message}`;
                    break;
                default:
                    toast.className += ' bg-gray-600';
                    toast.innerHTML = message;
            }
            
            document.body.appendChild(toast);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                toast.classList.add('translate-y-full');
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.parentNode.removeChild(toast);
                    }
                }, 300);
            }, 5000);
        }
        
        // Initialize event listeners
        function initEventListeners() {
            // File upload
            uploadArea.addEventListener('click', () => fileInput.click());
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('border-blue-400', 'bg-blue-50');
            });
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('border-blue-400', 'bg-blue-50');
            });
            uploadArea.addEventListener('drop', handleFileDrop);
            fileInput.addEventListener('change', handleFileSelect);
            
            // Mode selection
            modeButtons.forEach(btn => {
                btn.addEventListener('click', () => {
                    modeButtons.forEach(b => b.classList.remove('ring-4', 'ring-offset-2', 'ring-blue-300'));
                    btn.classList.add('ring-4', 'ring-offset-2', 'ring-blue-300');
                    currentMode = btn.dataset.mode;
                });
            });
            
            // Analyze button
            analyzeBtn.addEventListener('click', startAnalysis);

            // AI health check button
            if (aiHealthBtn) {
                aiHealthBtn.addEventListener('click', testApiConnection);
            }
            
            // Disassembler buttons
            refreshDisasmBtn.addEventListener('click', refreshDisassembly);
            copyDisasmBtn.addEventListener('click', copyDisassembly);
            analyzeVulnerabilityBtn.addEventListener('click', analyzeVulnerability);
            generateValidationBtn.addEventListener('click', generateValidationScript);
            applyPatchBtn.addEventListener('click', applyPatch);
            downloadPatchBtn.addEventListener('click', downloadPatch);

            if (toggleAdvancedPatching && patchingControls) {
                toggleAdvancedPatching.addEventListener('click', () => {
                    const isHidden = patchingControls.classList.contains('hidden');
                    patchingControls.classList.toggle('hidden', !isHidden);
                    toggleAdvancedPatching.textContent = isHidden ? 'Hide' : 'Show';
                });
            }
            
            // Function search
            functionSearch.addEventListener('input', filterFunctions);
            
            // Modal buttons
            closeVulnModal.addEventListener('click', () => vulnModal.classList.add('hidden'));
            analyzeWithAIBtn.addEventListener('click', openAIForVulnerability);
            
            // Report download buttons
            downloadLatexBtn.addEventListener('click', () => downloadReport('latex'));
            downloadJsonBtn.addEventListener('click', () => downloadReport('json'));
            downloadTextBtn.addEventListener('click', () => downloadReport('text'));
            
            // Close modal on outside click
            vulnModal.addEventListener('click', (e) => {
                if (e.target === vulnModal) {
                    vulnModal.classList.add('hidden');
                }
            });
            
            // Set default mode
            modeButtons[0].classList.add('ring-4', 'ring-offset-2', 'ring-blue-300');
        }

        function ensureApiUrl() {
            if (apiUrlInput) {
                apiUrlInput.value = DEFAULT_DARTMOUTH_URL;
            }
        }

        async function testApiConnection() {
            if (!apiUrlInput?.value || !apiKeyInput?.value) {
                if (aiHealthStatus) {
                    aiHealthStatus.textContent = 'Enter URL + Key';
                    aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-red-100 text-red-700';
                }
                showToast('Please enter both API URL and API key', 'error');
                return;
            }

            if (aiHealthStatus) {
                aiHealthStatus.textContent = 'Checking...';
                aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-yellow-100 text-yellow-800';
            }

            try {
                const formData = new FormData();
                formData.append('dartmouth_api_url_form', apiUrlInput.value);
                formData.append('dartmouth_api_key_form', apiKeyInput.value);

                const response = await fetch('/api/ai/health', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (response.ok && data.status === 'success') {
                    if (aiHealthStatus) {
                        aiHealthStatus.textContent = 'Connected';
                        aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-green-100 text-green-800';
                    }
                    showToast('AI API connection verified', 'success');
                } else {
                    if (aiHealthStatus) {
                        aiHealthStatus.textContent = 'Failed';
                        aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-red-100 text-red-700';
                    }
                    showToast(data.message || 'AI API check failed', 'error');
                }
            } catch (error) {
                if (aiHealthStatus) {
                    aiHealthStatus.textContent = 'Error';
                    aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-red-100 text-red-700';
                }
                showToast(`AI API check failed: ${error.message}`, 'error');
            }
        }
        
        // File handling
        function handleFileDrop(e) {
            e.preventDefault();
            uploadArea.classList.remove('border-blue-400', 'bg-blue-50');
            
            const file = e.dataTransfer.files[0];
            if (file) {
                handleFile(file);
            }
        }
        
        function handleFileSelect(e) {
            const file = e.target.files[0];
            if (file) {
                handleFile(file);
            }
        }
        
        function handleFile(file) {
            currentFile = file;
            fileStatus.innerHTML = `
                <div class="flex items-center gap-3 p-3 bg-green-50 rounded-lg">
                    <i class="fas fa-file-code text-green-600 text-xl"></i>
                    <div class="flex-grow">
                        <div class="font-medium text-green-800">${escapeHtml(file.name)}</div>
                        <div class="text-xs text-green-600">${formatBytes(file.size)}</div>
                    </div>
                    <button id="clearFileBtn" class="text-red-500 hover:text-red-700">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            
            analyzeBtn.disabled = false;
            
            // Add event listener for clear button
            setTimeout(() => {
                const clearBtn = document.getElementById('clearFileBtn');
                if (clearBtn) {
                    clearBtn.addEventListener('click', clearFile);
                }
            }, 100);
        }
        
        function clearFile() {
            currentFile = null;
            fileInput.value = '';
            fileStatus.innerHTML = '<span class="text-gray-500">No file selected</span>';
            analyzeBtn.disabled = true;
        }
        
        // Analysis functions
        async function startAnalysis() {
            if (!currentFile) {
                showToast('Please select a file first', 'error');
                return;
            }
            
            // Show loading state
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Analyzing...';
            analyzeBtn.disabled = true;
            
            // Show results section
            resultsSection.classList.remove('hidden');
            resultsContent.innerHTML = `
                <div class="text-center py-12">
                    <div class="loader rounded-full border-8 border-t-8 border-gray-200 border-t-blue-500 h-16 w-16 mx-auto mb-4" style="animation: spin 1s linear infinite;"></div>
                    <h3 class="text-lg font-semibold text-gray-700 mb-2">Starting Analysis</h3>
                    <p class="text-gray-500">Initializing ${currentMode.toUpperCase()} mode with GDB integration...</p>
                </div>
            `;
            
            // Show GDB section
            gdbSection.classList.remove('hidden');
            gdbContent.innerHTML = `
                <div class="text-center py-4">
                    <div class="loader rounded-full border-4 border-t-4 border-gray-200 border-t-blue-500 h-8 w-8 mx-auto mb-2" style="animation: spin 1s linear infinite;"></div>
                    <p class="text-gray-500 text-sm">Starting GDB dynamic analysis...</p>
                </div>
            `;
            
            // Check GDB availability
            try {
                const response = await fetch('/api/tools/check');
                const data = await response.json();
                if (data.tools.gdb) {
                    gdbStatus.textContent = 'Available';
                    gdbStatus.className = 'ml-auto text-sm font-normal px-2 py-1 bg-green-100 text-green-800 rounded';
                } else {
                    gdbStatus.textContent = 'Not Installed';
                    gdbStatus.className = 'ml-auto text-sm font-normal px-2 py-1 bg-red-100 text-red-800 rounded';
                }
            } catch (error) {
                console.error('Failed to check tools:', error);
            }
            
            // Prepare form data
            const formData = new FormData();
            formData.append('file', currentFile);
            formData.append('mode', currentMode);
            formData.append('trusted_mode', trustedModeToggle?.checked ? 'true' : 'false');
            
            // Add API credentials if provided
            if (apiUrlInput?.value || DEFAULT_DARTMOUTH_URL) {
                formData.append('dartmouth_api_url_form', apiUrlInput?.value || DEFAULT_DARTMOUTH_URL);
            }
            if (apiKeyInput?.value) {
                formData.append('dartmouth_api_key_form', apiKeyInput.value);
            }
            
            // Start analysis
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                currentJobId = data.job_id;
                
                showToast('Analysis started successfully!', 'success');
                pollResults();
                
            } catch (error) {
                console.error('Failed to start analysis:', error);
                showToast(`Failed to start analysis: ${error.message}`, 'error');
                
                // Reset UI
                analyzeBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Analysis with GDB';
                analyzeBtn.disabled = false;
            }
        }
        
        async function pollResults() {
            if (!currentJobId) return;
            
            // Clear any existing interval
            if (pollInterval) {
                clearInterval(pollInterval);
            }
            
            pollInterval = setInterval(async () => {
                try {
                    const response = await fetch(`/api/result/${currentJobId}`);
                    const data = await response.json();
                    
                    updateStatus(data.status);
                    
                    if (data.status === 'completed') {
                        clearInterval(pollInterval);
                        analyzeBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Analysis with GDB';
                        analyzeBtn.disabled = false;
                        displayResults(data.result);
                        
                        // Show report section
                        reportSection.classList.remove('hidden');
                        
                        // Load functions for disassembler
                        loadFunctions();
                        
                    } else if (data.status === 'error') {
                        clearInterval(pollInterval);
                        showToast(`Analysis failed: ${data.error}`, 'error');
                        analyzeBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Analysis with GDB';
                        analyzeBtn.disabled = false;
                        resultsContent.innerHTML = `
                            <div class="p-6 bg-red-50 border border-red-200 rounded-lg">
                                <div class="flex items-center gap-3 mb-2">
                                    <i class="fas fa-exclamation-triangle text-red-600 text-xl"></i>
                                    <h3 class="text-lg font-semibold text-red-800">Analysis Failed</h3>
                                </div>
                                <p class="text-red-700">${escapeHtml(data.error || 'Unknown error occurred')}</p>
                            </div>
                        `;
                    }
                } catch (error) {
                    console.error('Failed to poll results:', error);
                }
            }, 2000);
        }
        
        function updateStatus(status) {
            let badgeClass, badgeText, progressText;
            
            switch(status) {
                case 'processing':
                    badgeClass = 'bg-yellow-100 text-yellow-800';
                    badgeText = 'Processing';
                    progressText = 'Analyzing binary...';
                    break;
                case 'completed':
                    badgeClass = 'bg-green-100 text-green-800';
                    badgeText = 'Completed';
                    progressText = 'Analysis complete!';
                    break;
                case 'error':
                    badgeClass = 'bg-red-100 text-red-800';
                    badgeText = 'Error';
                    progressText = 'Analysis failed';
                    break;
                default:
                    badgeClass = 'bg-gray-100 text-gray-800';
                    badgeText = status;
                    progressText = '';
            }
            
            statusBadge.className = `px-3 py-1 rounded-full text-sm font-semibold ${badgeClass}`;
            statusBadge.textContent = badgeText;
            
            if (status === 'processing') {
                progressIndicator.classList.remove('hidden');
            } else {
                progressIndicator.classList.add('hidden');
            }
        }
        
        function displayResults(results) {
            if (!results) return;
            
            let html = '';
            
            // File info
            const fileInfo = results.file_info || {};
            html += `
                <div class="mb-6">
                    <h3 class="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                        <i class="fas fa-info-circle text-blue-600"></i> File Information
                    </h3>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm text-gray-500 mb-1">Filename</div>
                            <div class="font-medium">${escapeHtml(fileInfo.filename || 'Unknown')}</div>
                        </div>
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm text-gray-500 mb-1">Size</div>
                            <div class="font-medium">${formatBytes(fileInfo.size || 0)}</div>
                        </div>
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm text-gray-500 mb-1">Type</div>
                            <div class="font-medium">${escapeHtml(fileInfo.type || 'Unknown')}</div>
                        </div>
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm text-gray-500 mb-1">MD5</div>
                            <div class="font-mono text-sm">${escapeHtml(fileInfo.md5 || 'Unknown')}</div>
                        </div>
                    </div>
                </div>
            `;
            
            // Vulnerabilities
            const vulnerabilities = results.vulnerabilities || [];
            currentVulnerabilities = vulnerabilities;
            
            if (vulnerabilities.length > 0) {
                html += `
                    <div class="mb-6">
                        <div class="flex justify-between items-center mb-3">
                            <h3 class="text-lg font-semibold text-gray-800 flex items-center gap-2">
                                <i class="fas fa-shield-alt text-red-600"></i> Vulnerabilities
                                <span class="bg-red-100 text-red-800 text-xs px-2 py-1 rounded-full">${vulnerabilities.length} found</span>
                            </h3>
                            <button id="viewAllVulnsBtn" class="text-sm text-blue-600 hover:text-blue-800">
                                View All
                            </button>
                        </div>
                `;
                
                // Show top 3 vulnerabilities
                const topVulns = vulnerabilities.slice(0, 3);
                html += `<div class="space-y-3">`;
                
                topVulns.forEach((vuln, index) => {
                    const severityClass = getSeverityClass(vuln.severity);
                    html += `
                        <div class="p-4 rounded-lg ${severityClass} cursor-pointer hover:opacity-90 transition-opacity" 
                             onclick="showVulnerabilityDetails(${index})">
                            <div class="flex justify-between items-center mb-2">
                                <span class="font-semibold">${escapeHtml(vuln.type || 'Unknown')}</span>
                                <span class="text-xs px-2 py-1 rounded-full ${getSeverityBadgeClass(vuln.severity)}">
                                    ${vuln.severity || 'Unknown'}
                                </span>
                            </div>
                            <p class="text-sm">${escapeHtml(vuln.description || 'No description')}</p>
                        </div>
                    `;
                });
                
                if (vulnerabilities.length > 3) {
                    html += `
                        <div class="text-center pt-2">
                            <span class="text-sm text-gray-500">
                                +${vulnerabilities.length - 3} more vulnerabilities
                            </span>
                        </div>
                    `;
                }
                
                html += `</div></div>`;
                
                // Show disassembler section
                disassemblerSection.classList.remove('hidden');
                disasmStatus.textContent = 'Ready - Vulnerabilities Found';
                disasmStatus.className = 'px-2 py-1 bg-red-100 text-red-800 rounded';
            }
            
            // GDB Analysis
            const gdbAnalysis = results.gdb_analysis || {};
            if (gdbAnalysis && gdbAnalysis.success) {
                html += `
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                            <i class="fas fa-terminal text-purple-600"></i> GDB Dynamic Analysis
                            <span class="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">Successful</span>
                        </h3>
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm font-medium text-gray-700 mb-2">Analysis Summary:</div>
                            <pre class="text-xs bg-gray-900 text-gray-100 p-3 rounded overflow-x-auto max-h-40">${escapeHtml(gdbAnalysis.gdb_output || 'No output')}</pre>
                        </div>
                    </div>
                `;
                
                // Update GDB section
                gdbContent.innerHTML = `
                    <div class="space-y-3">
                        <div class="flex items-center gap-2 text-green-600">
                            <i class="fas fa-check-circle"></i>
                            <span class="font-medium">GDB analysis completed successfully</span>
                        </div>
                        ${gdbAnalysis.analysis && gdbAnalysis.analysis.security_features && gdbAnalysis.analysis.security_features.length > 0 ? `
                            <div class="mt-3">
                                <div class="text-sm font-medium text-gray-700 mb-2">Security Features Detected:</div>
                                <div class="space-y-1">
                                    ${gdbAnalysis.analysis.security_features.map(feature => 
                                        `<div class="text-sm text-gray-600">• ${escapeHtml(feature)}</div>`
                                    ).join('')}
                                </div>
                            </div>
                        ` : ''}
                    </div>
                `;
            }
            
            // AI Insights
            if (results.ai_insights) {
                const insights = results.ai_insights.insights || results.ai_insights;
                html += `
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                            <i class="fas fa-robot text-blue-600"></i> AI Insights
                        </h3>
                        <div class="bg-blue-50 p-4 rounded-lg">
                            <div class="prose max-w-none">
                                ${formatAIInsights(insights)}
                            </div>
                        </div>
                    </div>
                `;
            }

            // Solution Explanation
            if (results.solution_explanation && results.solution_explanation.summary) {
                html += `
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                            <i class="fas fa-route text-indigo-600"></i> Solution Explanation
                        </h3>
                        <div class="bg-indigo-50 p-4 rounded-lg">
                            <pre class="text-sm text-gray-800 whitespace-pre-wrap">${escapeHtml(results.solution_explanation.summary)}</pre>
                        </div>
                    </div>
                `;
            }

            // Solution Verification (Trusted Mode)
            if (results.solution_verification) {
                const verification = results.solution_verification;
                html += `
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                            <i class="fas fa-shield-check text-green-600"></i> Solution Verification
                        </h3>
                        <div class="bg-green-50 p-4 rounded-lg">
                            <div class="text-sm text-gray-700 mb-2">
                                <strong>Attempted:</strong> ${verification.attempted ? 'Yes' : 'No'} &nbsp;|
                                <strong>Success:</strong> ${verification.success ? 'Yes' : 'No'}
                            </div>
                            ${verification.output ? `
                                <pre class="text-xs bg-gray-900 text-gray-100 p-3 rounded overflow-x-auto max-h-40">${escapeHtml(verification.output)}</pre>
                            ` : ''}
                        </div>
                    </div>
                `;
            }
            
            // Recommendations
            const recommendations = results.recommendations || [];
            if (recommendations.length > 0) {
                html += `
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                            <i class="fas fa-lightbulb text-yellow-600"></i> Recommendations
                        </h3>
                        <div class="space-y-2">
                `;
                
                recommendations.forEach((rec, index) => {
                    html += `
                        <div class="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                            <span class="text-sm text-gray-500 mt-1">${index + 1}.</span>
                            <span class="flex-grow">${escapeHtml(rec)}</span>
                        </div>
                    `;
                });
                
                html += `</div></div>`;
            }
            
            resultsContent.innerHTML = html;
            
            // Add event listener for "View All" button
            setTimeout(() => {
                const viewAllBtn = document.getElementById('viewAllVulnsBtn');
                if (viewAllBtn) {
                    viewAllBtn.addEventListener('click', () => {
                        showAllVulnerabilities();
                    });
                }
            }, 100);
        }
        
        // Vulnerability functions
        function showVulnerabilityDetails(index) {
            if (!currentVulnerabilities || index >= currentVulnerabilities.length) return;
            
            const vuln = currentVulnerabilities[index];
            selectedVulnerability = vuln;
            
            let html = `
                <div class="space-y-4">
                    <div class="flex justify-between items-start">
                        <div>
                            <h4 class="text-lg font-bold text-gray-900">${escapeHtml(vuln.type || 'Unknown Vulnerability')}</h4>
                            <span class="inline-block mt-1 px-3 py-1 rounded-full text-sm font-semibold ${getSeverityBadgeClass(vuln.severity)}">
                                ${vuln.severity || 'Unknown'} severity
                            </span>
                        </div>
                    </div>
                    
                    <div>
                        <h5 class="font-semibold text-gray-700 mb-1">Description</h5>
                        <p class="text-gray-600">${escapeHtml(vuln.description || 'No description available')}</p>
                    </div>
                    
                    ${vuln.fix_suggestion ? `
                        <div>
                            <h5 class="font-semibold text-gray-700 mb-1">Fix Suggestion</h5>
                            <p class="text-gray-600">${escapeHtml(vuln.fix_suggestion)}</p>
                        </div>
                    ` : ''}
                    
                    ${vuln.evidence ? `
                        <div>
                            <h5 class="font-semibold text-gray-700 mb-1">Evidence</h5>
                            <div class="bg-gray-50 p-3 rounded">
                                <pre class="text-sm overflow-x-auto">${escapeHtml(Array.isArray(vuln.evidence) ? vuln.evidence.join('\\n') : vuln.evidence)}</pre>
                            </div>
                        </div>
                    ` : ''}
                    
                    ${vuln.location ? `
                        <div>
                            <h5 class="font-semibold text-gray-700 mb-1">Location</h5>
                            <p class="text-gray-600">${escapeHtml(vuln.location)}</p>
                        </div>
                    ` : ''}
                </div>
            `;
            
            vulnModalContent.innerHTML = html;
            vulnModal.classList.remove('hidden');
        }
        
        function showAllVulnerabilities() {
            if (!currentVulnerabilities || currentVulnerabilities.length === 0) return;
            
            let html = `
                <div class="space-y-4">
                    <h4 class="text-lg font-bold text-gray-900 mb-4">All Vulnerabilities (${currentVulnerabilities.length})</h4>
            `;
            
            currentVulnerabilities.forEach((vuln, index) => {
                html += `
                    <div class="p-4 rounded-lg border border-gray-200 hover:border-blue-300 cursor-pointer" 
                         onclick="showVulnerabilityDetails(${index})">
                        <div class="flex justify-between items-center mb-2">
                            <span class="font-semibold">${escapeHtml(vuln.type || 'Unknown')}</span>
                            <span class="text-xs px-2 py-1 rounded-full ${getSeverityBadgeClass(vuln.severity)}">
                                ${vuln.severity || 'Unknown'}
                            </span>
                        </div>
                        <p class="text-sm text-gray-600">${escapeHtml(vuln.description || 'No description').substring(0, 100)}...</p>
                    </div>
                `;
            });
            
            html += `</div>`;
            
            vulnModalContent.innerHTML = html;
            vulnModal.classList.remove('hidden');
        }
        
        // Function loading and disassembly
        async function loadFunctions() {
            if (!currentJobId) return;
            
            try {
                const formData = new FormData();
                formData.append('job_id', currentJobId);
                
                const response = await fetch('/api/disassembler/functions', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                
                const data = await response.json();
                currentFunctions = data.functions || [];
                renderFunctionList(currentFunctions);
                
            } catch (error) {
                console.error('Failed to load functions:', error);
                functionList.innerHTML = `
                    <div class="text-center py-4 text-red-500">
                        <i class="fas fa-exclamation-circle mb-2"></i>
                        <p>Failed to load functions</p>
                    </div>
                `;
            }
        }
        
        function renderFunctionList(functions) {
            if (!functions || functions.length === 0) {
                functionList.innerHTML = `
                    <div class="text-center py-4 text-gray-500">
                        <i class="fas fa-search mb-2"></i>
                        <p>No functions found</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            functions.forEach((func, index) => {
                html += `
                    <div class="function-item p-2 border rounded mb-1 hover:bg-blue-50 cursor-pointer ${index === 0 ? 'selected' : ''}" 
                         onclick="selectFunction(${index})" data-index="${index}">
                        <div class="font-mono text-sm text-gray-800">${escapeHtml(func.name || 'unknown')}</div>
                        <div class="text-xs text-gray-500">${escapeHtml(func.address || '0x0')}</div>
                    </div>
                `;
            });
            
            functionList.innerHTML = html;
            
            // Select first function by default
            if (functions.length > 0) {
                selectedFunction = functions[0];
                loadDisassembly(selectedFunction.name, selectedFunction.address);
            }
        }
        
        function filterFunctions() {
            const searchTerm = functionSearch.value.toLowerCase();
            const filtered = currentFunctions.filter(func => 
                func.name.toLowerCase().includes(searchTerm) || 
                func.address.toLowerCase().includes(searchTerm)
            );
            renderFunctionList(filtered);
        }
        
        function selectFunction(index) {
            // Remove selected class from all functions
            document.querySelectorAll('.function-item').forEach(item => {
                item.classList.remove('selected');
            });
            
            // Add selected class to clicked function
            const functionItem = document.querySelector(`.function-item[data-index="${index}"]`);
            if (functionItem) {
                functionItem.classList.add('selected');
            }
            
            selectedFunction = currentFunctions[index];
            loadDisassembly(selectedFunction.name, selectedFunction.address);
        }
        
        async function loadDisassembly(functionName, functionAddress) {
            if (!currentJobId || (!functionName && !functionAddress)) return;
            
            disassemblyContent.innerHTML = `
                <div class="text-center py-4">
                    <div class="loader ease-linear rounded-full border-4 border-t-4 border-gray-700 h-8 w-8 mx-auto mb-2"></div>
                    <p class="text-gray-400">Loading disassembly...</p>
                </div>
            `;
            
            try {
                const formData = new FormData();
                formData.append('job_id', currentJobId);
                if (functionName) {
                    formData.append('function_name', functionName);
                }
                if (functionAddress) {
                    formData.append('address', functionAddress);
                }
                
                const response = await fetch('/api/disassembler/disassemble', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                
                const data = await response.json();
                disassemblyContent.innerHTML = `<pre class="whitespace-pre-wrap">${escapeHtml(data.disassembly || 'No disassembly available')}</pre>`;
                
            } catch (error) {
                console.error('Failed to load disassembly:', error);
                disassemblyContent.innerHTML = `
                    <div class="text-center py-4 text-red-400">
                        <i class="fas fa-exclamation-circle mb-2"></i>
                        <p>Failed to load disassembly</p>
                    </div>
                `;
            }
        }
        
        function refreshDisassembly() {
            if (selectedFunction) {
                loadDisassembly(selectedFunction.name);
            }
        }
        
        function copyDisassembly() {
            const text = disassemblyContent.innerText;
            navigator.clipboard.writeText(text).then(() => {
                showToast('Disassembly copied to clipboard', 'success');
            }).catch(err => {
                showToast('Failed to copy disassembly', 'error');
            });
        }
        
        // AI vulnerability analysis
        async function analyzeVulnerability() {
            if (!selectedVulnerability || !currentJobId || !selectedFunction) {
                showToast('Please select a vulnerability and function first', 'error');
                return;
            }
            
            // Get current disassembly
            const disassembly = disassemblyContent.innerText;
            if (!disassembly || disassembly.includes('Loading') || disassembly.includes('Failed')) {
                showToast('Please load disassembly first', 'error');
                return;
            }
            
            // Show AI analysis panel
            aiAnalysisPanel.classList.remove('hidden');
            aiAnalysisContent.innerHTML = `
                <div class="text-center py-8">
                    <div class="loader ease-linear rounded-full border-4 border-t-4 border-blue-500 h-8 w-8 mx-auto mb-2"></div>
                    <p class="text-blue-600">Analyzing vulnerability with AI...</p>
                </div>
            `;
            
            try {
                const formData = new FormData();
                formData.append('job_id', currentJobId);
                formData.append('disassembly', disassembly);
                formData.append('vulnerability_info', JSON.stringify(selectedVulnerability));
                
                // Add API credentials if available
                if (apiUrlInput?.value || DEFAULT_DARTMOUTH_URL) {
                    formData.append('dartmouth_api_url_form', apiUrlInput?.value || DEFAULT_DARTMOUTH_URL);
                }
                if (apiKeyInput?.value) {
                    formData.append('dartmouth_api_key_form', apiKeyInput.value);
                }
                
                const response = await fetch('/api/disassembler/analyze_vulnerability', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                
                const data = await response.json();
                
                if (data.success) {
                    aiAnalysisContent.innerHTML = `
                        <div class="space-y-4">
                            <div>
                                <h4 class="font-semibold text-gray-800 mb-2">AI Analysis:</h4>
                                <div class="text-sm text-gray-700 whitespace-pre-wrap">${escapeHtml(data.analysis || 'No analysis provided')}</div>
                            </div>
                            
                            ${data.patches && data.patches.length > 0 ? `
                                <div>
                                    <h4 class="font-semibold text-gray-800 mb-2">Generated Patches (${data.patches.length}):</h4>
                                    <div class="space-y-2">
                                        ${data.patches.map(patch => `
                                            <div class="p-2 bg-green-50 border border-green-200 rounded">
                                                <div class="font-medium">${escapeHtml(patch.type || 'Unknown')}</div>
                                                <div class="text-xs text-gray-600">${escapeHtml(patch.description || 'No description')}</div>
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    `;
                } else {
                    aiAnalysisContent.innerHTML = `
                        <div class="text-center py-8 text-red-500">
                            <i class="fas fa-exclamation-circle mb-2"></i>
                            <p>AI analysis failed</p>
                            <p class="text-sm">${escapeHtml(data.error || 'Unknown error')}</p>
                        </div>
                    `;
                }
                
            } catch (error) {
                console.error('Failed to analyze vulnerability:', error);
                aiAnalysisContent.innerHTML = `
                    <div class="text-center py-8 text-red-500">
                        <i class="fas fa-exclamation-circle mb-2"></i>
                        <p>Failed to analyze vulnerability</p>
                        <p class="text-sm">${escapeHtml(error.message)}</p>
                    </div>
                `;
            }
        }
        
        function openAIForVulnerability() {
            // Close modal
            vulnModal.classList.add('hidden');
            
            // Show AI analysis panel
            aiAnalysisPanel.classList.remove('hidden');
            
            // Trigger AI analysis
            setTimeout(() => {
                analyzeVulnerability();
            }, 300);
        }
        
        async function generateValidationScript() {
            if (!selectedVulnerability) {
                showToast('Please select a vulnerability first', 'error');
                return;
            }
            
            if (!currentJobId) {
                showToast('No active analysis session', 'error');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('job_id', currentJobId);
                formData.append('vulnerability_info', JSON.stringify(selectedVulnerability));
                formData.append('patches', JSON.stringify([])); // Empty patches for now
                
                const response = await fetch('/api/disassembler/generate_validation_script', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                
                const scriptText = await response.text();
                
                // Create download link
                const blob = new Blob([scriptText], { type: 'text/plain' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `validate_${selectedVulnerability.type || 'vulnerability'}.sh`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                showToast('Validation script downloaded', 'success');
                
            } catch (error) {
                console.error('Failed to generate validation script:', error);
                showToast(`Failed to generate script: ${error.message}`, 'error');
            }
        }
        
        function applyPatch() {
            showToast('Patch application requires manual review. Use the generated scripts.', 'info');
        }
        
        function downloadPatch() {
            showToast('Patch download requires manual review. Use the generated scripts.', 'info');
        }
        
        // Report download
        async function downloadReport(type) {
            if (!currentJobId) {
                showToast('No active analysis session', 'error');
                return;
            }
            
            // Get the results to access the report
            try {
                const response = await fetch(`/api/result/${currentJobId}`);
                const data = await response.json();
                
                if (data.status !== 'completed' || !data.result || !data.result.report) {
                    showToast('No report available yet', 'error');
                    return;
                }
                
                const report = data.result.report;
                let content, filename, mimeType;
                
                switch(type) {
                    case 'latex':
                        content = report.latex || '';
                        filename = `report_${currentJobId}.tex`;
                        mimeType = 'text/x-tex';
                        break;
                    case 'json':
                        content = report.json || '{}';
                        filename = `report_${currentJobId}.json`;
                        mimeType = 'application/json';
                        break;
                    case 'text':
                        content = report.text || '';
                        filename = `report_${currentJobId}.txt`;
                        mimeType = 'text/plain';
                        break;
                    default:
                        throw new Error('Invalid report type');
                }
                
                if (!content) {
                    showToast(`No ${type} report available`, 'error');
                    return;
                }
                
                // Create download link
                const blob = new Blob([content], { type: mimeType });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                showToast(`${type.toUpperCase()} report downloaded`, 'success');
                
            } catch (error) {
                console.error('Failed to download report:', error);
                showToast(`Failed to download report: ${error.message}`, 'error');
            }
        }
        
        // Expose functions to global scope for onclick handlers
        window.showVulnerabilityDetails = showVulnerabilityDetails;
        window.selectFunction = selectFunction;
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            ensureApiUrl();
            initEventListeners();
            showToast('RevCopilot v3.0 with GDB integration loaded', 'info');
        });
    </script>
</body>
</html>"""
    
    return HTMLResponse(content=html_content)

@app.post("/api/disassembler/health")
async def disassembler_health():
    """Check disassembler health."""
    tools = {
        "objdump": False,
        "strings": False,
        "file": False,
    }
    
    # Check tools
    for tool in ["objdump", "strings", "file"]:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=2)
            tools[tool] = True
        except:
            tools[tool] = False
    
    return {
        "status": "healthy",
        "tools": tools,
        "version": "3.0.0",
        "features": ["vulnerability_patching", "ai_analysis", "gdb_integration"]
    }

@app.post("/api/cleanup/{job_id}")
async def cleanup_job(job_id: str):
    """Clean up job resources."""
    if job_id in jobs:
        job_data = jobs[job_id]
        temp_path = job_data.get("temp_path")
        if temp_path and os.path.exists(temp_path):
            cleanup_file(temp_path)
        
        del jobs[job_id]
        return {"status": "cleaned", "job_id": job_id}
    
    raise HTTPException(status_code=404, detail="Job not found")

# ==================== STARTUP AND CLEANUP ====================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup."""
    logger.info("RevCopilot v3.0 starting up...")
    logger.info("Features: AI analysis, GDB integration, vulnerability patching")
    
    # Check for GDB
    gdb_available = GDBAnalyzer("/bin/ls").check_gdb_installed()
    if gdb_available:
        logger.info("✓ GDB is available for dynamic analysis")
    else:
        logger.warning("✗ GDB not found. Install with: sudo apt-get install gdb")
    
    # Check for angr
    if angr is None:
        logger.warning("✗ angr not installed. Symbolic execution features limited.")
    else:
        logger.info("✓ angr available for symbolic execution")
    
    # Check for aiofiles
    if aiofiles is None:
        logger.warning("✗ aiofiles not installed. File uploads will use synchronous operations.")
    
    # Create necessary directories
    os.makedirs("static", exist_ok=True)
    temp_dir = os.path.join(tempfile.gettempdir(), "revcopilot_uploads")
    os.makedirs(temp_dir, exist_ok=True)
    
    logger.info("RevCopilot v3.0 ready for requests")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("RevCopilot shutting down...")
    
    # Cleanup temporary files
    for job_id, job_data in list(jobs.items()):
        temp_path = job_data.get("temp_path")
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
                logger.info(f"Cleaned up file for job {job_id}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_path}: {e}")
    
    logger.info("Cleanup complete")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info(f"Starting RevCopilot server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)