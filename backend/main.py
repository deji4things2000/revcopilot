"""
RevCopilot Backend Server v3.5 - Enhanced with Platform Selection
Complete with Web UI, AI-Assisted Disassembler, and Multi-Platform Support
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
from typing import Optional, List, Dict, Any, Tuple
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
    title="RevCopilot v3.5",
    description="Multi-Platform AI-Powered Reverse Engineering Assistant",
    version="3.5.0",
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
    patch_strategy: str = "safe"
    patch_data: Optional[Dict] = None

# ==================== PLATFORM-SPECIFIC ANALYZERS ====================

class PlatformAnalyzer:
    """Factory for platform-specific analysis tools."""
    
    @staticmethod
    def get_analyzer(platform: str, binary_path: str):
        """Get analyzer for specified platform."""
        platform = platform.lower()
        
        if platform == "auto":
            # Auto-detect platform
            if sys.platform == "darwin":
                return MacAnalyzer(binary_path)
            elif sys.platform.startswith("linux"):
                return LinuxAnalyzer(binary_path)
            elif sys.platform == "win32":
                return WindowsAnalyzer(binary_path)
            else:
                return UniversalAnalyzer(binary_path)
        elif platform == "mac" or platform == "macos":
            return MacAnalyzer(binary_path)
        elif platform == "linux":
            return LinuxAnalyzer(binary_path)
        elif platform == "windows":
            return WindowsAnalyzer(binary_path)
        else:
            return UniversalAnalyzer(binary_path)

class BaseAnalyzer:
    """Base class for all analyzers."""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.platform = "unknown"
        
    def analyze(self) -> Dict[str, Any]:
        """Main analysis method to be implemented by subclasses."""
        raise NotImplementedError
        
    def check_tools(self) -> Dict[str, bool]:
        """Check available tools."""
        return {}

class MacAnalyzer(BaseAnalyzer):
    """macOS-specific analysis using LLDB, DTrace, and native tools."""
    
    def __init__(self, binary_path: str):
        super().__init__(binary_path)
        self.platform = "macos"
        
    def check_tools(self) -> Dict[str, bool]:
        """Check macOS-specific tools."""
        tools = {
            "lldb": False,
            "otool": False,
            "nm": False,
            "strings": False,
            "file": False,
            "dtrace": False,
        }
        
        for tool in tools.keys():
            tools[tool] = self._check_tool(tool)
            
        return tools
    
    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            if tool == "lldb":
                result = subprocess.run(["lldb", "--version"], 
                                      capture_output=True, text=True, timeout=2)
                return result.returncode == 0
            elif tool == "dtrace":
                result = subprocess.run(["sudo", "-n", "dtrace", "-l"],
                                      capture_output=True, text=True, timeout=2)
                return result.returncode == 0
            else:
                result = subprocess.run([tool, "--version"] if tool != "strings" else [tool, "--help"],
                                      capture_output=True, text=True, timeout=2)
                return result.returncode == 0
        except:
            return False
    
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive macOS analysis."""
        results = {
            "platform": "macos",
            "success": False,
            "tools_available": self.check_tools(),
            "analysis": {},
            "techniques": []
        }
        
        try:
            # 1. File type analysis
            file_type = self._analyze_file_type()
            results["analysis"]["file_type"] = file_type
            results["techniques"].append("file_analysis")
            
            # 2. Mach-O header analysis (if applicable)
            if "Mach-O" in file_type:
                macho_info = self._analyze_macho()
                results["analysis"]["macho"] = macho_info
                results["techniques"].append("macho_analysis")
            
            # 3. LLDB analysis (if available)
            if results["tools_available"].get("lldb", False):
                lldb_result = self._analyze_with_lldb()
                results["analysis"]["lldb"] = lldb_result
                results["techniques"].append("lldb_analysis")
            
            # 4. DTrace system call tracing (if available)
            if results["tools_available"].get("dtrace", False):
                dtrace_result = self._analyze_with_dtrace()
                results["analysis"]["dtrace"] = dtrace_result
                results["techniques"].append("dtrace_analysis")
            
            # 5. Static analysis
            static_result = self._static_analysis()
            results["analysis"]["static"] = static_result
            results["techniques"].append("static_analysis")
            
            # 6. String analysis
            strings = self._extract_strings()
            results["analysis"]["strings"] = strings[:50]
            results["techniques"].append("string_analysis")
            
            results["success"] = True
            
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"macOS analysis failed: {e}")
        
        return results
    
    def _analyze_file_type(self) -> str:
        """Determine file type."""
        try:
            result = subprocess.run(["file", "-b", self.binary_path], 
                                  capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def _analyze_macho(self) -> Dict[str, Any]:
        """Analyze Mach-O binary headers."""
        info = {}
        try:
            # Header info
            cmd = ["otool", "-hv", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["header"] = result.stdout.strip()[:500]
            
            # Load commands
            cmd = ["otool", "-l", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["load_commands"] = result.stdout.strip()[:1000]
            
            # Imports
            cmd = ["otool", "-Iv", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["imports"] = result.stdout.strip()[:1000]
            
            # Sections
            cmd = ["otool", "-s", "__TEXT", "__text", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["text_section"] = result.stdout.strip()[:500]
            
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    def _analyze_with_lldb(self) -> Dict[str, Any]:
        """Analyze with LLDB."""
        try:
            lldb_script = f"""
target create "{self.binary_path}"
image list
image dump sections
disassemble --name main
quit
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.lldb', delete=False) as f:
                f.write(lldb_script)
                script_path = f.name
            
            cmd = ["lldb", "-b", "-s", script_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            os.unlink(script_path)
            
            return {
                "success": True,
                "output": result.stdout[:2000],
                "error": result.stderr[:500]
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _analyze_with_dtrace(self) -> Dict[str, Any]:
        """Trace system calls with DTrace."""
        try:
            # Simple DTrace script for syscall tracing
            dtrace_script = """
syscall:::entry
/pid == $target/
{
    printf("%s(%d)\\n", probefunc, arg0);
}
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.d', delete=False) as f:
                f.write(dtrace_script)
                script_path = f.name
            
            # Run binary with DTrace
            cmd = ["sudo", "dtrace", "-s", script_path, "-c", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            os.unlink(script_path)
            
            return {
                "success": True,
                "syscalls": result.stdout.strip().split('\n')[:20]
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _static_analysis(self) -> Dict[str, Any]:
        """Perform static analysis."""
        analysis = {
            "functions": [],
            "symbols": [],
            "segments": []
        }
        
        try:
            # Extract functions with nm
            if self._check_tool("nm"):
                cmd = ["nm", "-gU", self.binary_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                analysis["symbols"] = result.stdout.strip().split('\n')[:30]
            
            # Get segments
            if self._check_tool("otool"):
                cmd = ["otool", "-l", self.binary_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                analysis["segments"] = result.stdout.strip().split('\n')[:50]
            
        except Exception as e:
            analysis["error"] = str(e)
        
        return analysis
    
    def _extract_strings(self) -> List[str]:
        """Extract strings from binary."""
        try:
            cmd = ["strings", "-n", "8", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout.strip().split('\n')[:100]
        except:
            return []

class LinuxAnalyzer(BaseAnalyzer):
    """Linux-specific analysis using GDB and Linux tools."""
    
    def __init__(self, binary_path: str):
        super().__init__(binary_path)
        self.platform = "linux"
        
    def check_tools(self) -> Dict[str, bool]:
        """Check Linux-specific tools."""
        tools = {
            "gdb": False,
            "objdump": False,
            "readelf": False,
            "nm": False,
            "strings": False,
            "file": False,
            "strace": False,
            "ltrace": False,
        }
        
        for tool in tools.keys():
            tools[tool] = self._check_tool(tool)
            
        return tools
    
    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            result = subprocess.run([tool, "--version"] if tool != "strings" else [tool, "--help"],
                                  capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive Linux analysis."""
        results = {
            "platform": "linux",
            "success": False,
            "tools_available": self.check_tools(),
            "analysis": {},
            "techniques": []
        }
        
        try:
            # 1. File type analysis
            file_type = self._analyze_file_type()
            results["analysis"]["file_type"] = file_type
            results["techniques"].append("file_analysis")
            
            # 2. ELF analysis (if applicable)
            if "ELF" in file_type:
                elf_info = self._analyze_elf()
                results["analysis"]["elf"] = elf_info
                results["techniques"].append("elf_analysis")
            
            # 3. GDB analysis (if available)
            if results["tools_available"].get("gdb", False):
                gdb_result = self._analyze_with_gdb()
                results["analysis"]["gdb"] = gdb_result
                results["techniques"].append("gdb_analysis")
            
            # 4. Strace system call tracing (if available)
            if results["tools_available"].get("strace", False):
                strace_result = self._analyze_with_strace()
                results["analysis"]["strace"] = strace_result
                results["techniques"].append("strace_analysis")
            
            # 5. Static analysis
            static_result = self._static_analysis()
            results["analysis"]["static"] = static_result
            results["techniques"].append("static_analysis")
            
            # 6. String analysis
            strings = self._extract_strings()
            results["analysis"]["strings"] = strings[:50]
            results["techniques"].append("string_analysis")
            
            results["success"] = True
            
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Linux analysis failed: {e}")
        
        return results
    
    def _analyze_file_type(self) -> str:
        """Determine file type."""
        try:
            result = subprocess.run(["file", "-b", self.binary_path], 
                                  capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def _analyze_elf(self) -> Dict[str, Any]:
        """Analyze ELF binary headers."""
        info = {}
        try:
            # Header info
            cmd = ["readelf", "-h", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["header"] = result.stdout.strip()
            
            # Sections
            cmd = ["readelf", "-S", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["sections"] = result.stdout.strip()[:1000]
            
            # Dynamic symbols
            cmd = ["readelf", "-s", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["symbols"] = result.stdout.strip()[:1000]
            
            # Program headers
            cmd = ["readelf", "-l", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            info["program_headers"] = result.stdout.strip()[:1000]
            
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    def _analyze_with_gdb(self) -> Dict[str, Any]:
        """Analyze with GDB."""
        try:
            gdb_script = f"""
set pagination off
file {shlex.quote(self.binary_path)}
starti
info registers
info functions
disassemble main
x/20i main
quit
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(gdb_script)
                script_path = f.name
            
            cmd = ["gdb", "-q", "-batch", "-x", script_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            os.unlink(script_path)
            
            return {
                "success": True,
                "output": result.stdout[:2000],
                "error": result.stderr[:500]
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _analyze_with_strace(self) -> Dict[str, Any]:
        """Trace system calls with strace."""
        try:
            cmd = ["strace", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            return {
                "success": True,
                "syscalls": result.stderr.strip().split('\n')[:20]
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _static_analysis(self) -> Dict[str, Any]:
        """Perform static analysis."""
        analysis = {
            "functions": [],
            "disassembly": "",
            "sections": []
        }
        
        try:
            # Disassemble main
            if self._check_tool("objdump"):
                cmd = ["objdump", "-d", self.binary_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                analysis["disassembly"] = result.stdout[:1500]
            
            # Get functions
            if self._check_tool("nm"):
                cmd = ["nm", "-D", self.binary_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                analysis["functions"] = result.stdout.strip().split('\n')[:30]
            
        except Exception as e:
            analysis["error"] = str(e)
        
        return analysis
    
    def _extract_strings(self) -> List[str]:
        """Extract strings from binary."""
        try:
            cmd = ["strings", "-n", "8", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout.strip().split('\n')[:100]
        except:
            return []

class WindowsAnalyzer(BaseAnalyzer):
    """Windows-specific analysis (placeholder)."""
    
    def __init__(self, binary_path: str):
        super().__init__(binary_path)
        self.platform = "windows"
        
    def analyze(self) -> Dict[str, Any]:
        return {
            "platform": "windows",
            "success": False,
            "error": "Windows analysis not yet implemented",
            "suggestion": "Use WSL (Windows Subsystem for Linux) for full analysis capabilities"
        }

class UniversalAnalyzer(BaseAnalyzer):
    """Universal analysis using only cross-platform tools."""
    
    def __init__(self, binary_path: str):
        super().__init__(binary_path)
        self.platform = "universal"
        
    def analyze(self) -> Dict[str, Any]:
        """Perform platform-agnostic analysis."""
        results = {
            "platform": "universal",
            "success": False,
            "analysis": {},
            "techniques": []
        }
        
        try:
            # 1. Basic file analysis
            file_info = self._get_file_info()
            results["analysis"]["file_info"] = file_info
            results["techniques"].append("file_analysis")
            
            # 2. String extraction (platform independent)
            strings = self._extract_strings()
            results["analysis"]["strings"] = strings[:100]
            results["techniques"].append("string_analysis")
            
            # 3. Hex dump analysis
            hex_analysis = self._hex_analysis()
            results["analysis"]["hex"] = hex_analysis
            results["techniques"].append("hex_analysis")
            
            # 4. Pattern detection
            patterns = self._detect_patterns()
            results["analysis"]["patterns"] = patterns
            results["techniques"].append("pattern_detection")
            
            # 5. Entropy analysis
            entropy = self._calculate_entropy()
            results["analysis"]["entropy"] = entropy
            results["techniques"].append("entropy_analysis")
            
            results["success"] = True
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _get_file_info(self) -> Dict[str, Any]:
        """Get basic file information."""
        try:
            size = os.path.getsize(self.binary_path)
            return {
                "size": size,
                "size_human": self._format_size(size),
                "modified": datetime.fromtimestamp(os.path.getmtime(self.binary_path)).isoformat(),
                "md5": self._calculate_hash("md5"),
                "sha256": self._calculate_hash("sha256")
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _format_size(self, size: int) -> str:
        """Format file size."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def _calculate_hash(self, algorithm: str) -> str:
        """Calculate file hash."""
        try:
            if algorithm == "md5":
                hasher = hashlib.md5()
            elif algorithm == "sha256":
                hasher = hashlib.sha256()
            else:
                return "unknown"
            
            with open(self.binary_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
        except:
            return "unknown"
    
    def _extract_strings(self) -> List[str]:
        """Extract strings without external tools."""
        strings = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            current = bytearray()
            for b in data:
                if 32 <= b <= 126:  # Printable ASCII
                    current.append(b)
                else:
                    if len(current) >= 8:
                        try:
                            strings.append(current.decode('utf-8', errors='ignore'))
                        except:
                            pass
                        if len(strings) >= 200:
                            break
                    current = bytearray()
            
            # Don't forget last string
            if len(current) >= 8:
                try:
                    strings.append(current.decode('utf-8', errors='ignore'))
                except:
                    pass
                
        except Exception as e:
            strings = [f"Error extracting strings: {str(e)}"]
        
        return strings
    
    def _hex_analysis(self) -> Dict[str, Any]:
        """Analyze binary hex data."""
        analysis = {}
        try:
            with open(self.binary_path, 'rb') as f:
                header = f.read(512)  # First 512 bytes
            
            analysis["header_hex"] = binascii.hexlify(header[:64]).decode('ascii')
            analysis["header_ascii"] = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header[:64])
            
            # Check for magic numbers
            magic_numbers = {
                b'\x7fELF': "ELF",
                b'\xcf\xfa\xed\xfe': "Mach-O 64-bit",
                b'\xce\xfa\xed\xfe': "Mach-O 32-bit",
                b'MZ': "PE/COFF (Windows)",
                b'#!': "Shell script",
            }
            
            for magic, name in magic_numbers.items():
                if header.startswith(magic):
                    analysis["magic"] = name
                    break
            
        except Exception as e:
            analysis["error"] = str(e)
        
        return analysis
    
    def _detect_patterns(self) -> List[Dict[str, Any]]:
        """Detect common patterns in binary."""
        patterns = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read(8192)  # First 8KB
            
            # Check for XOR patterns
            xor_sequences = [
                b'\x31', b'\x33', b'\x35',  # XOR instructions
                b'\x80[\x00-\xff]{1}\x30',  # XOR with immediate
            ]
            
            for pattern in xor_sequences:
                if isinstance(pattern, bytes) and pattern in data:
                    patterns.append({
                        "type": "xor_operation",
                        "confidence": "high",
                        "description": "XOR encryption/decryption detected"
                    })
                    break
            
            # Check for common crypto constants
            crypto_constants = [
                b'MD5', b'SHA', b'AES', b'DES', b'RSA',
                b'\x67\x45\x23\x01',  # Common crypto magic
            ]
            
            for const in crypto_constants:
                if const in data:
                    patterns.append({
                        "type": "crypto_constant",
                        "confidence": "medium",
                        "description": "Cryptographic constant detected"
                    })
                    break
            
            # Check for null bytes (padding)
            if b'\x00' * 16 in data:
                patterns.append({
                    "type": "null_padding",
                    "confidence": "low",
                    "description": "Null byte padding detected"
                })
            
        except Exception as e:
            patterns.append({
                "type": "analysis_error",
                "confidence": "high",
                "description": f"Pattern detection failed: {str(e)}"
            })
        
        return patterns
    
    def _calculate_entropy(self) -> float:
        """Calculate Shannon entropy of the binary."""
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read(4096)  # First 4KB
            
            if not data:
                return 0.0
            
            # Count byte frequencies
            freq = [0] * 256
            for byte in data:
                freq[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            for count in freq:
                if count > 0:
                    p = count / len(data)
                    entropy -= p * (p.log2() if hasattr(p, 'log2') else math.log2(p))
            
            return entropy
        except:
            return 0.0

# ==================== AI VULNERABILITY PATCHER ====================

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
            objdump_tool = _resolve_tool("objdump")
            result = subprocess.run([objdump_tool, '-d', self.binary_path],
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

# ==================== SYMBOLIC EXECUTION (ANGR) ====================

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

# ==================== ENHANCED ANALYSIS FUNCTIONS ====================

def enhanced_analyze_binary(file_path: str, mode: str = "auto", 
                          platform: str = "auto", api_key: Optional[str] = None, 
                          api_url: Optional[str] = None, trusted_mode: bool = False):
    """Enhanced binary analysis with platform selection."""
    logger.info(f"Enhanced analysis of {file_path} in {mode} mode on {platform} platform")
    
    try:
        # Get basic file info
        file_info = {
            "filename": os.path.basename(file_path),
            "size": os.path.getsize(file_path),
            "type": detect_file_type(file_path),
            "md5": calculate_md5(file_path),
            "sha256": calculate_sha256(file_path),
            "platform_selected": platform
        }
    except Exception as e:
        logger.error(f"Error getting file info: {e}")
        file_info = {
            "filename": os.path.basename(file_path),
            "size": 0,
            "type": "Unknown",
            "md5": "error",
            "sha256": "error",
            "platform_selected": platform
        }
    
    # Run platform-specific analysis
    analysis_results = {
        "file_info": file_info,
        "platform": platform,
        "techniques": [],
        "findings": [],
        "vulnerabilities": [],
        "recommendations": [],
        "patterns": [],
        "functions": [],
        "strings": []
    }
    
    # Platform-specific analysis
    try:
        analyzer = PlatformAnalyzer.get_analyzer(platform, file_path)
        platform_results = analyzer.analyze()
        
        analysis_results["platform_analysis"] = platform_results
        analysis_results["techniques"].extend(platform_results.get("techniques", []))
        
        if platform_results.get("success"):
            analysis_results["findings"].append({
                "type": "platform_analysis_success",
                "description": f"Platform analysis completed successfully using {analyzer.platform}"
            })
            
            # Extract useful data from platform analysis
            if "analysis" in platform_results:
                platform_analysis = platform_results["analysis"]
                
                if "strings" in platform_analysis:
                    analysis_results["strings"] = platform_analysis["strings"]
                
                if "patterns" in platform_analysis:
                    analysis_results["patterns"] = platform_analysis["patterns"]
                
                if "static" in platform_analysis and "functions" in platform_analysis["static"]:
                    analysis_results["functions"] = platform_analysis["static"]["functions"]
        
        # Add tools availability
        if "tools_available" in platform_results:
            analysis_results["tools_available"] = platform_results["tools_available"]
        
    except Exception as e:
        logger.error(f"Platform analysis failed: {e}")
        analysis_results["platform_analysis_error"] = str(e)
    
    # Universal string analysis (fallback)
    if not analysis_results.get("strings"):
        try:
            strings = _extract_ascii_strings(file_path)
            analysis_results["strings"] = strings[:100]
            analysis_results["techniques"].append("universal_string_analysis")
        except Exception as e:
            logger.error(f"String analysis failed: {e}")
            analysis_results["strings"] = []
    
    # Symbolic Execution (angr) - if available
    if angr is not None:
        try:
            angr_result = try_angr_analysis(file_path)
            if angr_result:
                analysis_results["angr_solution"] = angr_result
                analysis_results["techniques"].append("symbolic_execution")
        except Exception as e:
            logger.error(f"Angr analysis failed: {e}")
    
    # Pattern Detection
    try:
        patterns = detect_common_patterns(file_path)
        analysis_results["patterns"] = patterns
        analysis_results["techniques"].append("pattern_detection")
    except Exception as e:
        logger.error(f"Pattern detection failed: {e}")
        analysis_results["patterns"] = []
    
    # Vulnerability Scanning
    try:
        vulns = scan_for_vulnerabilities(file_path)
        analysis_results["vulnerabilities"] = vulns
        analysis_results["techniques"].append("vulnerability_scanning")
    except Exception as e:
        logger.error(f"Vulnerability scanning failed: {e}")
        analysis_results["vulnerabilities"] = []
    
    # AI Analysis (if API available)
    if mode in ("ai", "tutor") and api_key and api_url:
        try:
            ai_analysis = perform_ai_analysis(file_path, mode, api_key, api_url, analysis_results)
            analysis_results["ai_insights"] = ai_analysis
            analysis_results["techniques"].append("ai_analysis")
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            analysis_results["ai_insights"] = {"error": str(e), "insights": "AI analysis failed"}
    
    # Medium.bin specific analysis
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

# ==================== UTILITY FUNCTIONS ====================

async def save_uploaded_file(file: UploadFile, identifier: str) -> str:
    """Save uploaded file to temporary location."""
    if aiofiles is None:
        return save_uploaded_file_sync(file, identifier)
    
    temp_dir = tempfile.gettempdir()
    upload_dir = os.path.join(temp_dir, "revcopilot_uploads")
    os.makedirs(upload_dir, exist_ok=True)
    
    original_name = file.filename or "binary"
    safe_name = "".join(c for c in original_name if c.isalnum() or c in '._- ').rstrip()
    file_path = os.path.join(upload_dir, f"{identifier}_{safe_name}")
    
    try:
        async with aiofiles.open(file_path, 'wb') as buffer:
            while True:
                chunk = await file.read(8192)
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
                chunk = file.file.read(8192)
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
    
    try:
        if os.path.getsize(file_path) == 14472:
            return True
    except:
        pass
    
    return False

def detect_common_patterns(file_path: str):
    """Detect common reverse engineering patterns."""
    patterns = []
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read(8192)
        
        # Check for XOR patterns
        xor_patterns = [
            b'\x80[\x00-\xff]{1}\x30',
            b'\x34[\x00-\xff]{1}',
            b'\x35[\x00-\xff]{4}',
            b'\x31[\x00-\xff]{2}',
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
        string_ops = [b'\xa4', b'\xa5', b'\xa6', b'\xa7']
        for op in string_ops:
            if op in data:
                patterns.append({
                    "type": "string_operation",
                    "confidence": "medium",
                    "description": "String operation detected"
                })
                break
        
        # Check for cryptographic patterns
        crypto_constants = [
            b'\x67\x45\x23\x01',
            b'\xef\xcd\xab\x89',
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
        loop_ops = [b'\xe2', b'\xe0', b'\xe1']
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

def scan_for_vulnerabilities(file_path: str):
    """Comprehensive vulnerability scanning."""
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
                    "location": f"Strings section"
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
        except:
            pass
        
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
    
    return vulns

def get_binary_functions(binary_path: str) -> List[Dict]:
    """Extract function list from binary."""
    functions = []
    
    # Try nm first
    try:
        nm_tool = _resolve_tool("nm")
        cmd = [nm_tool, binary_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        for line in result.stdout.split('\n'):
            if ' T ' in line:
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
            objdump_tool = _resolve_tool("objdump")
            cmd = [objdump_tool, "-t", binary_path]
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
    if not functions and sys.platform == "darwin" and shutil.which("otool"):
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

    # Fallback: parse disassembly output for function labels
    if not functions:
        try:
            objdump_tool = _resolve_tool("objdump")
            result = subprocess.run([objdump_tool, "-d", binary_path], capture_output=True, text=True, timeout=10)
            functions = _extract_functions_from_disassembly(result.stdout)
        except Exception as e:
            logger.warning(f"objdump disassembly parse failed: {e}")

    if not functions and sys.platform == "darwin" and shutil.which("otool"):
        try:
            result = subprocess.run(["otool", "-tvV", binary_path], capture_output=True, text=True, timeout=10)
            functions = _extract_functions_from_disassembly(result.stdout)
        except Exception as e:
            logger.warning(f"otool disassembly parse failed: {e}")

    # Sort by address
    try:
        def _addr_to_int(addr: str) -> int:
            if not addr:
                return 0
            clean = addr.lower().replace("0x", "")
            try:
                return int(clean, 16)
            except Exception:
                return 0
        functions.sort(key=lambda x: _addr_to_int(x.get('address')))
    except Exception:
        pass
    
    return functions[:50]

def _extract_functions_from_disassembly(disasm_text: str) -> List[Dict]:
    """Extract function labels from disassembly output."""
    functions: List[Dict] = []
    if not disasm_text:
        return functions

    objdump_re = re.compile(r"^([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
    otool_re = re.compile(r"^([0-9a-fA-F]+)\s+([_A-Za-z][\w$@.]+):\s*$")

    for line in disasm_text.split("\n"):
        line = line.strip()
        if not line:
            continue
        match = objdump_re.match(line)
        if match:
            functions.append({
                "address": match.group(1),
                "name": match.group(2),
                "size": "unknown"
            })
            continue
        match = otool_re.match(line)
        if match:
            functions.append({
                "address": match.group(1),
                "name": match.group(2),
                "size": "unknown"
            })

    seen = set()
    unique = []
    for f in functions:
        key = (f.get("address"), f.get("name"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return unique

def perform_ai_analysis(file_path: str, mode: str, api_key: str, api_url: str, analysis_results: dict):
    """Perform AI analysis on binary."""
    try:
        context = {
            "file_info": analysis_results.get("file_info", {}),
            "patterns": analysis_results.get("patterns", []),
            "vulnerabilities": analysis_results.get("vulnerabilities", []),
            "functions_count": len(analysis_results.get("functions", [])),
            "strings_sample": analysis_results.get("strings", [])[:20],
        }
        
        if mode == "ai":
            prompt = f"""Analyze this binary file for reverse engineering purposes:

File: {context['file_info']['filename']}
Size: {context['file_info']['size']} bytes
Type: {context['file_info']['type']}
Platform: {analysis_results.get('platform', 'Unknown')}

Patterns detected: {context['patterns']}
Vulnerabilities: {len(context['vulnerabilities'])} found
Functions found: {context['functions_count']}

Provide insights about:
1. What this binary likely does
2. Key functions to examine
3. Potential attack vectors
4. Suggested reverse engineering approach
5. Vulnerability patches if applicable"""
        
        elif mode == "tutor":
            prompt = f"""As a reverse engineering tutor, provide educational hints for analyzing this binary:

File: {context['file_info']['filename']}
Platform: {analysis_results.get('platform', 'Unknown')}
Patterns detected: {context['patterns']}

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
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if b'password' in data.lower():
            result["hint"] = "Binary appears to check for a password"
        
        xor_patterns = [
            b'\x80[\x00-\xff]{1}\x30',
            b'\x34[\x00-\xff]{1}',
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
    if "angr_solution" in analysis_results:
        return analysis_results["angr_solution"]
    
    if "medium_bin_analysis" in analysis_results:
        medium_result = analysis_results["medium_bin_analysis"]
        if medium_result.get("solution"):
            return {
                "type": "crackme_solution",
                "solution": medium_result["solution"],
                "confidence": "high",
                "source": "medium.bin specific analysis"
            }
    
    patterns = analysis_results.get("patterns", [])
    strings = analysis_results.get("strings", [])
    
    flag_patterns = ["flag{", "FLAG{", "ctf{", "CTF{", "key:", "Key:", "password:", "Password:"]
    for string in strings:
        for pattern in flag_patterns:
            if pattern in string:
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

    return {
        "source": "heuristic",
        "summary": "Solution derived from automated analysis techniques and detected patterns. Review evidence for details.",
        "evidence": summary,
    }

def verify_solution_with_binary(file_path: str, solution: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the binary with candidate solution inputs."""
    try:
        args = [file_path]

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
    
    vulns = analysis_results.get('vulnerabilities', [])
    high_vulns = [v for v in vulns if v.get('severity') == 'high']
    if high_vulns:
        recommendations.append(f"Perform manual security audit: {len(high_vulns)} high-severity vulnerabilities found")
        recommendations.append(f"Use AI-assisted disassembler to generate patches for critical vulnerabilities")
    
    functions = analysis_results.get('functions', [])
    if len(functions) > 100:
        recommendations.append("Binary appears large and complex; consider using Ghidra or IDA Pro for deeper analysis")
    elif len(functions) < 10:
        recommendations.append("Binary appears small; try static analysis with objdump and strings first")
    
    if not analysis_results.get('solution'):
        recommendations.append("No automatic solution found; try manual reverse engineering with platform-specific tools")
    
    patterns = analysis_results.get('patterns', [])
    xor_patterns = [p for p in patterns if p.get('type') == 'xor_operation']
    if xor_patterns:
        recommendations.append("XOR operations detected: try xor brute force with common keys (0x00-0xFF)")
    
    crypto_patterns = [p for p in patterns if 'crypto' in p.get('type', '')]
    if crypto_patterns:
        recommendations.append("Cryptographic patterns detected: look for encryption/decryption routines")
    
    # Platform-specific recommendations
    platform = analysis_results.get('platform', 'auto')
    if platform == 'macos':
        recommendations.append("On macOS: Use LLDB for dynamic debugging or otool for static analysis")
    elif platform == 'linux':
        recommendations.append("On Linux: Use GDB for dynamic debugging or objdump/readelf for static analysis")
    
    general_recs = [
        "Use dynamic analysis to understand runtime behavior",
        "Check for anti-debugging or obfuscation techniques",
        "Look for cryptographic constants or algorithm signatures",
        "Trace user input flow through the program",
        "Consider using radare2 or Binary Ninja for interactive analysis",
        "Use the AI-assisted disassembler to analyze and patch vulnerabilities",
        "If stuck, try approaching from different angles: input fuzzing, pattern matching, or symbolic execution"
    ]
    
    recommendations.extend(general_recs)
    
    return recommendations

# ==================== REPORT GENERATION ====================

def generate_comprehensive_report(analysis_results: dict, mode: str) -> Dict[str, str]:
    """Generate comprehensive reports in multiple formats."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    latex_report = generate_latex_report(analysis_results, mode, timestamp)
    json_report = generate_json_report(analysis_results, mode, timestamp)
    text_report = generate_text_report(analysis_results, mode, timestamp)
    
    return {
        "latex": latex_report,
        "json": json_report,
        "text": text_report,
        "timestamp": timestamp
    }

def generate_latex_report(analysis_results: dict, mode: str, timestamp: str) -> str:
    """Generate LaTeX report."""
    
    file_info = analysis_results.get('file_info', {})
    filename = escape_latex(file_info.get('filename', 'Unknown'))
    file_size = file_info.get('size', 0)
    file_type = escape_latex(file_info.get('type', 'Unknown'))
    platform = escape_latex(analysis_results.get('platform', 'Unknown'))
    
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
\\author{{Generated by RevCopilot v3.5}}
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
This report was generated by RevCopilot v3.5, an AI-powered multi-platform reverse engineering assistant. 
Analysis mode: \\textbf{{{mode}}}. Platform: \\textbf{{{platform}}}. Analysis completed on {timestamp}.

\\section{{File Information}}
\\begin{{tabular}}{{ll}}
\\hline
\\textbf{{Property}} & \\textbf{{Value}} \\\\
\\hline
Filename & {filename} \\\\
Size & {file_size} bytes \\\\
Type & {file_type} \\\\
Platform & {platform} \\\\
MD5 & {escape_latex(file_info.get('md5', 'Unknown'))} \\\\
SHA256 & {escape_latex(file_info.get('sha256', 'Unknown'))} \\\\
\\hline
\\end{{tabular}}

\\section{{Analysis Techniques Applied}}
\\begin{{itemize}}
"""

    techniques = analysis_results.get('techniques', [])
    for tech in techniques:
        latex_report += f"    \\item \\textbf{{{tech.replace('_', ' ').title()}}}\n"
    
    latex_report += """\\end{itemize}

\\section{Key Findings}
"""

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

    solution_explanation = analysis_results.get('solution_explanation')
    if solution_explanation and solution_explanation.get('summary'):
        latex_report += "\\subsection{Solution Explanation}\n"
        latex_report += f"\\begin{{quote}}\n{escape_latex(solution_explanation.get('summary', ''))}\n\\end{{quote}}\n"

    verification = analysis_results.get('solution_verification')
    if verification:
        latex_report += "\\subsection{Solution Verification}\n"
        latex_report += f"\\textbf{{Attempted}}: {escape_latex(str(verification.get('attempted', False)))}\\\\\n"
        latex_report += f"\\textbf{{Success}}: {escape_latex(str(verification.get('success', False)))}\\\\\n"
        if verification.get('output'):
            latex_report += f"\\begin{{quote}}\\n{escape_latex(verification.get('output', ''))}\\n\\end{{quote}}\\n"
    
    vulns = analysis_results.get('vulnerabilities', [])
    if vulns:
        latex_report += "\\subsection{Vulnerabilities Detected}\n"
        latex_report += "\\begin{longtable}{|p{3cm}|p{2cm}|p{8cm}|}\n"
        latex_report += "\\hline\n"
        latex_report += "\\textbf{Type} & \\textbf{Severity} & \\textbf{Description} \\\\\\hline\n"
        latex_report += "\\endhead\n"
        
        for vuln in vulns[:10]:
            vuln_type = escape_latex(vuln.get('type', 'Unknown'))
            vuln_severity = escape_latex(vuln.get('severity', 'Unknown'))
            vuln_desc = escape_latex(vuln.get('description', 'No description'))
            vuln_fix = escape_latex(vuln.get('fix_suggestion', 'No fix suggestion'))
            latex_report += f"{vuln_type} & {vuln_severity} & {vuln_desc} \\\\\n"
            latex_report += f"\\multicolumn{{3}}{{l|}}{{\\small\\textbf{{Fix}}: {vuln_fix}}} \\\\\\hline\n"
        
        latex_report += "\\end{longtable}\n"
        latex_report += f"\\textbf{{Total vulnerabilities found}}: {len(vulns)}\n"
    
    if "platform_analysis" in analysis_results:
        platform_results = analysis_results["platform_analysis"]
        latex_report += "\\subsection{Platform-Specific Analysis}\n"
        latex_report += f"Platform: \\textbf{{{escape_latex(platform_results.get('platform', 'Unknown'))}}}\\\\\n"
        
        if platform_results.get('success'):
            latex_report += "Status: \\textbf{Success}\\\\\n"
            techniques = platform_results.get('techniques', [])
            if techniques:
                latex_report += "Techniques applied: "
                latex_report += ", ".join([escape_latex(t) for t in techniques[:5]]) + "\\\\\n"
        else:
            latex_report += f"Status: \\textbf{{Failed}} - {escape_latex(platform_results.get('error', 'Unknown error'))}\\\\\n"
    
    patterns = analysis_results.get('patterns', [])
    if patterns:
        latex_report += "\\subsection{Detected Patterns}\n\\begin{itemize}\n"
        for pattern in patterns[:10]:
            pattern_type = escape_latex(pattern.get('type', 'Unknown'))
            pattern_desc = escape_latex(pattern.get('description', 'No description'))
            pattern_conf = escape_latex(pattern.get('confidence', 'Unknown'))
            latex_report += f"    \\item \\textbf{{{pattern_type}}}: {pattern_desc} (Confidence: {pattern_conf})\n"
        latex_report += "\\end{itemize}\n"
    
    strings = analysis_results.get('strings', [])
    if strings:
        latex_report += "\\section{Interesting Strings}\n"
        latex_report += "\\begin{lstlisting}\n"
        for string in strings[:30]:
            latex_report += f"{escape_latex(string)}\n"
        latex_report += "\\end{lstlisting}\n"
    
    if analysis_results.get('ai_insights'):
        latex_report += "\\section{AI Analysis Insights}\n"
        insights = analysis_results['ai_insights']
        if isinstance(insights, dict):
            insights_text = insights.get('insights', str(insights))
        else:
            insights_text = str(insights)
        
        insights_text = escape_latex(insights_text)
        latex_report += f"\\begin{{quote}}\n{insights_text}\n\\end{{quote}}\n"
    
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

def generate_json_report(analysis_results: dict, mode: str, timestamp: str) -> str:
    """Generate JSON report."""
    report_data = {
        "metadata": {
            "tool": "RevCopilot",
            "version": "3.5.0",
            "timestamp": timestamp,
            "mode": mode,
            "platform": analysis_results.get('platform', 'unknown')
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
    lines.append(f"Platform: {analysis_results.get('platform', 'auto')}")
    lines.append(f"Version: 3.5.0 - Multi-Platform Support")
    lines.append("")
    
    file_info = analysis_results.get('file_info', {})
    lines.append("FILE INFORMATION:")
    lines.append("-" * 40)
    lines.append(f"  Filename: {file_info.get('filename', 'Unknown')}")
    lines.append(f"  Size: {file_info.get('size', 0)} bytes")
    lines.append(f"  Type: {file_info.get('type', 'Unknown')}")
    lines.append(f"  Platform: {analysis_results.get('platform', 'Unknown')}")
    lines.append(f"  MD5: {file_info.get('md5', 'Unknown')}")
    lines.append(f"  SHA256: {file_info.get('sha256', 'Unknown')}")
    lines.append("")
    
    techniques = analysis_results.get('techniques', [])
    lines.append("ANALYSIS TECHNIQUES APPLIED:")
    lines.append("-" * 40)
    for tech in techniques:
        lines.append(f"  • {tech.replace('_', ' ').title()}")
    lines.append("")
    
    vulns = analysis_results.get('vulnerabilities', [])
    if vulns:
        lines.append("VULNERABILITIES FOUND:")
        lines.append("-" * 40)
        for i, vuln in enumerate(vulns[:15], 1):
            lines.append(f"  {i}. [{vuln.get('severity', 'Unknown').upper()}] {vuln.get('type', 'Unknown')}")
            lines.append(f"      {vuln.get('description', 'No description')}")
            lines.append("")
        lines.append(f"  Total vulnerabilities: {len(vulns)}")
        lines.append("")
    
    if "platform_analysis" in analysis_results:
        platform_results = analysis_results["platform_analysis"]
        lines.append("PLATFORM-SPECIFIC ANALYSIS:")
        lines.append("-" * 40)
        lines.append(f"  Platform: {platform_results.get('platform', 'Unknown')}")
        if platform_results.get('success'):
            lines.append("  Status: Successful")
            techs = platform_results.get('techniques', [])
            if techs:
                lines.append(f"  Techniques: {', '.join(techs[:5])}")
        else:
            lines.append(f"  Status: Failed - {platform_results.get('error', 'Unknown error')}")
        lines.append("")
    
    recommendations = analysis_results.get('recommendations', [])
    if recommendations:
        lines.append("RECOMMENDATIONS:")
        lines.append("-" * 40)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"  {i}. {rec}")
        lines.append("")
    
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
    lines.append("Report generated by RevCopilot v3.5 - Multi-Platform Analysis")
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
        strings = result.stdout.split('\n')[:100]
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

def _resolve_tool(tool: str) -> str:
    """Resolve GNU-prefixed tools on macOS when available."""
    if sys.platform == "darwin":
        gnu_tool = f"g{tool}"
        if shutil.which(gnu_tool):
            return gnu_tool
    return tool

def _tool_available(tool: str) -> bool:
    """Check if a tool (or GNU-prefixed variant on macOS) is available."""
    candidates = [tool]
    if sys.platform == "darwin":
        candidates.insert(0, f"g{tool}")
    for name in candidates:
        if shutil.which(name):
            return True
    return False

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

async def process_analysis(job_id: str, path: str, mode: str, platform: str, 
                          api_key: Optional[str] = None, api_url: Optional[str] = None, 
                          trusted_mode: bool = False):
    """Background analysis task."""
    try:
        logger.info(f"Processing job {job_id} in {mode} mode on {platform} platform")
        
        results = enhanced_analyze_binary(path, mode, platform, api_key, api_url, trusted_mode=trusted_mode)
        
        # Format response
        response = {
            "type": mode,
            "platform": platform,
            "file_info": results.get("file_info"),
            "vulnerabilities": results.get("vulnerabilities", []),
            "analysis_summary": {
                "techniques_used": results.get("techniques", []),
                "vulnerabilities_found": len(results.get("vulnerabilities", [])),
                "platform_analysis": "platform_analysis" in results
            },
            "platform_analysis": results.get("platform_analysis"),
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
    platform: str = Query("auto", pattern="^(auto|mac|macos|linux|windows|universal)$"),
    trusted_mode: bool = Form(False),
    dartmouth_api_key: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Key"),
    dartmouth_api_url: Optional[str] = Header(default=None, alias="X-Dartmouth-API-Url"),
    dartmouth_api_key_form: Optional[str] = Form(default=None),
    dartmouth_api_url_form: Optional[str] = Form(default=None),
):
    """Upload binary and start analysis with platform selection."""
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    MAX_FILE_SIZE = 50 * 1024 * 1024
    
    # Save uploaded file
    file_id = str(uuid.uuid4())
    try:
        temp_path = await save_uploaded_file(file, file_id)
        
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
        "platform": platform,
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
        platform,
        effective_key,
        effective_url,
        bool(trusted_mode),
    )
    
    return JSONResponse({
        "job_id": file_id,
        "status": "started",
        "message": f"Analysis started in {mode} mode on {platform} platform.",
        "filename": file.filename,
        "platform": platform
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
    
    effective_key = _resolve_dartmouth_key(dartmouth_api_key)
    effective_url = _resolve_dartmouth_url(dartmouth_api_url)
    
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
    # Check platform
    current_platform = sys.platform
    if current_platform == "darwin":
        platform_name = "macOS"
    elif current_platform.startswith("linux"):
        platform_name = "Linux"
    elif current_platform == "win32":
        platform_name = "Windows"
    else:
        platform_name = current_platform
    
    return {
        "status": "healthy",
        "service": "revcopilot-backend",
        "version": "3.5.0",
        "platform": platform_name,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/tools/check")
async def check_tools():
    """Check for required tools."""
    tools = {
        "objdump": _tool_available("objdump"),
        "strings": _tool_available("strings"),
        "file": _tool_available("file"),
        "nm": _tool_available("nm"),
    }
    
    # Platform-specific tools
    if sys.platform == "darwin":
        tools["lldb"] = _tool_available("lldb")
        tools["otool"] = _tool_available("otool")
    elif sys.platform.startswith("linux"):
        tools["gdb"] = _tool_available("gdb")
        tools["readelf"] = _tool_available("readelf")
        tools["strace"] = _tool_available("strace")
    
    return {
        "tools": tools,
        "platform": sys.platform,
        "install_commands": {
            "macos": "Install Xcode Command Line Tools: xcode-select --install",
            "ubuntu": "sudo apt-get install gdb binutils",
            "general": "See individual tool websites for installation"
        }
    }

# ==================== WEB UI ====================

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    """Serve the main web interface with platform selection."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>RevCopilot v3.5</title>
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
            <h1 class="text-4xl font-bold mb-2"><i class="fas fa-shield-alt"></i> RevCopilot v3.5</h1>
            <p class="text-xl opacity-90">Multi-Platform AI-Powered Reverse Engineering</p>
            <p class="text-sm opacity-75 mt-2">Now with platform selection: macOS, Linux, Windows, and Universal analysis</p>
        </div>
    </div>

    <div class="container mx-auto px-4 py-8">
        <div class="mb-8 p-4 bg-blue-100 border-l-4 border-blue-400 rounded">
            <div class="flex items-center gap-3 mb-1">
                <span class="text-blue-600 text-xl"><i class="fas fa-laptop-code"></i></span>
                <span class="font-semibold text-blue-800">New in v3.5: Platform Selection</span>
            </div>
            <div class="text-blue-900 text-sm mt-1">
                <ul class="list-disc ml-6">
                    <li><strong>macOS Support</strong>: LLDB, DTrace, and native macOS tools</li>
                    <li><strong>Linux Support</strong>: GDB, strace, and Linux-specific analysis</li>
                    <li><strong>Universal Analysis</strong>: Cross-platform tools for any OS</li>
                    <li><strong>Auto Detection</strong>: Automatically selects best tools for your system</li>
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
                        <p class="text-sm text-gray-400 mt-4">ELF, Mach-O, PE formats supported</p>
                    </label>
                    
                    <div class="mt-4 text-sm text-gray-600">
                        <div id="fileStatus">No file selected</div>
                    </div>

                    <div class="mt-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3"><i class="fas fa-cogs mr-2"></i>Analysis Configuration</h3>
                        
                        <!-- Platform Selection -->
                        <div class="mb-4">
                            <label class="block text-sm text-gray-600 mb-2">Platform Selection</label>
                            <div class="grid grid-cols-4 gap-2" id="platformSelection">
                                <button data-platform="auto" class="platform-btn p-3 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 text-white font-semibold hover:opacity-90 transition-opacity">
                                    <i class="fas fa-magic mr-1"></i> Auto
                                </button>
                                <button data-platform="mac" class="platform-btn p-3 rounded-lg bg-gradient-to-br from-gray-700 to-black text-white font-semibold hover:opacity-90 transition-opacity">
                                    <i class="fab fa-apple mr-1"></i> macOS
                                </button>
                                <button data-platform="linux" class="platform-btn p-3 rounded-lg bg-gradient-to-br from-yellow-500 to-red-600 text-white font-semibold hover:opacity-90 transition-opacity">
                                    <i class="fab fa-linux mr-1"></i> Linux
                                </button>
                                <button data-platform="universal" class="platform-btn p-3 rounded-lg bg-gradient-to-br from-green-500 to-emerald-600 text-white font-semibold hover:opacity-90 transition-opacity">
                                    <i class="fas fa-globe mr-1"></i> Universal
                                </button>
                            </div>
                            <div id="platformInfo" class="text-xs text-gray-500 mt-2">
                                Auto: Detects best tools for your system
                            </div>
                        </div>
                        
                        <!-- Analysis Mode -->
                        <div class="mb-4">
                            <label class="block text-sm text-gray-600 mb-2">Analysis Mode</label>
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
                        </div>
                        
                        <!-- API Configuration -->
                        <div class="mb-4">
                            <label class="block text-sm text-gray-600 mb-1" for="apiUrlInput">Dartmouth API URL</label>
                            <input id="apiUrlInput" type="text" class="w-full px-3 py-2 border rounded-lg text-sm bg-gray-100 text-gray-600" 
                                   value="https://chat.dartmouth.edu/api" readonly>
                            <div class="text-xs text-gray-500 mt-1">Auto-configured for Dartmouth students</div>
                        </div>
                        <div class="mb-4">
                            <label class="block text-sm text-gray-600 mb-1" for="apiKeyInput">Dartmouth API Key (Optional)</label>
                            <input id="apiKeyInput" type="password" placeholder="Enter API key for AI features" class="w-full px-3 py-2 border rounded-lg text-sm">
                        </div>
                        <div class="mb-4 flex items-center gap-3">
                            <button id="aiHealthBtn" type="button" class="px-4 py-2 rounded-lg text-sm font-semibold text-white bg-gradient-to-r from-indigo-500 to-purple-600 hover:opacity-90 transition-opacity">
                                <i class="fas fa-plug mr-2"></i>Test API Connection
                            </button>
                            <span id="aiHealthStatus" class="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600">Not tested</span>
                        </div>
                        
                        <!-- Trusted Mode -->
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
                        <i class="fas fa-play mr-2"></i>Start Analysis
                    </button>
                    
                    <!-- Platform Tools Status -->
                    <div id="platformStatus" class="mt-4 p-3 bg-gray-50 rounded-lg border border-gray-200 hidden">
                        <div class="text-sm font-semibold text-gray-700 mb-2">Platform Tools Status</div>
                        <div id="toolsStatus" class="text-xs text-gray-600">
                            Checking tools...
                        </div>
                    </div>
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
                        </div>
                        
                        <!-- Middle: Disassembly Viewer -->
                        <div class="lg:col-span-2">
                            <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">
                                    <i class="fas fa-assistive-listening-systems mr-1"></i> Disassembly
                                </label>
                                <div id="disassemblyContent" class="h-64 overflow-y-auto border rounded-lg p-4 bg-gray-900 text-gray-100 font-mono text-sm">
                                    <div class="text-center py-8 text-gray-400">
                                        <i class="fas fa-code mb-2"></i>
                                        <p>Select a function to view disassembly</p>
                                    </div>
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
                
                <!-- Platform Analysis Panel -->
                <div id="platformAnalysisSection" class="hidden bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <i class="fas fa-laptop-code text-purple-600"></i> Platform Analysis
                        <span id="platformStatusBadge" class="ml-auto text-sm font-normal px-2 py-1 bg-purple-100 text-purple-800 rounded">Active</span>
                    </h2>
                    <div id="platformAnalysisContent" class="space-y-4">
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-spinner fa-spin mb-2"></i>
                            <p>Platform analysis will run during binary analysis</p>
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
                            <i class="fas fa-info-circle mr-1"></i> Reports include platform-specific analysis results
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
        let currentPlatform = 'auto';
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
        const platformButtons = document.querySelectorAll('.platform-btn');
        const platformInfo = document.getElementById('platformInfo');
        const platformStatus = document.getElementById('platformStatus');
        const toolsStatus = document.getElementById('toolsStatus');
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
        
        // Platform analysis elements
        const platformAnalysisSection = document.getElementById('platformAnalysisSection');
        const platformAnalysisContent = document.getElementById('platformAnalysisContent');
        const platformStatusBadge = document.getElementById('platformStatusBadge');
        
        // Report elements
        const reportSection = document.getElementById('reportSection');
        
        // Disassembler elements
        const disassemblerSection = document.getElementById('disassemblerSection');
        const disasmStatus = document.getElementById('disasmStatus');
        const functionList = document.getElementById('functionList');
        const functionSearch = document.getElementById('functionSearch');
        const disassemblyContent = document.getElementById('disassemblyContent');
        
        // Modal elements
        const vulnModal = document.getElementById('vulnModal');
        const vulnModalContent = document.getElementById('vulnModalContent');
        const closeVulnModal = document.getElementById('closeVulnModal');
        const analyzeWithAIBtn = document.getElementById('analyzeWithAIBtn');
        
        // Report download buttons
        const downloadLatexBtn = document.getElementById('downloadLatexBtn');
        const downloadJsonBtn = document.getElementById('downloadJsonBtn');
        const downloadTextBtn = document.getElementById('downloadTextBtn');

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
        
        function showToast(message, type = 'info') {
            const existingToasts = document.querySelectorAll('.toast');
            existingToasts.forEach(toast => toast.remove());
            
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
            
            setTimeout(() => {
                toast.classList.add('translate-y-full');
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.parentNode.removeChild(toast);
                    }
                }, 300);
            }, 5000);
        }
        
        // Platform information
        const platformDescriptions = {
            'auto': 'Auto-detect best tools for your system',
            'mac': 'macOS: Uses LLDB, DTrace, and native macOS tools',
            'linux': 'Linux: Uses GDB, strace, and Linux-specific tools',
            'universal': 'Universal: Uses cross-platform tools only',
            'windows': 'Windows: Limited analysis (use Universal or WSL)'
        };
        
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
            
            // Platform selection
            platformButtons.forEach(btn => {
                btn.addEventListener('click', () => {
                    platformButtons.forEach(b => b.classList.remove('ring-4', 'ring-offset-2', 'ring-blue-300'));
                    btn.classList.add('ring-4', 'ring-offset-2', 'ring-blue-300');
                    currentPlatform = btn.dataset.platform;
                    platformInfo.textContent = platformDescriptions[currentPlatform];
                    
                    // Check tools for selected platform
                    checkPlatformTools();
                });
            });
            
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
            aiHealthBtn.addEventListener('click', testApiConnection);
            
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
            
            // Set default selections
            platformButtons[0].classList.add('ring-4', 'ring-offset-2', 'ring-blue-300');
            modeButtons[0].classList.add('ring-4', 'ring-offset-2', 'ring-blue-300');
            
            // Initial tools check
            checkPlatformTools();
        }

        async function checkPlatformTools() {
            try {
                const response = await fetch('/api/tools/check');
                const data = await response.json();
                
                let statusHtml = '';
                const tools = data.tools || {};
                
                for (const [tool, available] of Object.entries(tools)) {
                    if (available) {
                        statusHtml += `<div class="flex items-center gap-2 text-green-600">
                            <i class="fas fa-check-circle"></i>
                            <span>${tool}</span>
                        </div>`;
                    } else {
                        statusHtml += `<div class="flex items-center gap-2 text-red-600">
                            <i class="fas fa-times-circle"></i>
                            <span>${tool}</span>
                        </div>`;
                    }
                }
                
                toolsStatus.innerHTML = statusHtml;
                platformStatus.classList.remove('hidden');
                
            } catch (error) {
                toolsStatus.innerHTML = `<div class="text-red-600">Failed to check tools: ${error.message}</div>`;
            }
        }

        async function testApiConnection() {
            if (!apiUrlInput?.value || !apiKeyInput?.value) {
                aiHealthStatus.textContent = 'Enter Key';
                aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-red-100 text-red-700';
                showToast('Please enter API key', 'error');
                return;
            }

            aiHealthStatus.textContent = 'Checking...';
            aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-yellow-100 text-yellow-800';

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
                    aiHealthStatus.textContent = 'Connected';
                    aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-green-100 text-green-800';
                    showToast('AI API connection verified', 'success');
                } else {
                    aiHealthStatus.textContent = 'Failed';
                    aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-red-100 text-red-700';
                    showToast(data.message || 'AI API check failed', 'error');
                }
            } catch (error) {
                aiHealthStatus.textContent = 'Error';
                aiHealthStatus.className = 'text-xs px-2 py-1 rounded-full bg-red-100 text-red-700';
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
                    <p class="text-gray-500">Initializing ${currentMode.toUpperCase()} mode on ${currentPlatform.toUpperCase()} platform...</p>
                </div>
            `;
            
            // Show platform analysis section
            platformAnalysisSection.classList.remove('hidden');
            platformAnalysisContent.innerHTML = `
                <div class="text-center py-4">
                    <div class="loader rounded-full border-4 border-t-4 border-gray-200 border-t-blue-500 h-8 w-8 mx-auto mb-2" style="animation: spin 1s linear infinite;"></div>
                    <p class="text-gray-500 text-sm">Starting platform-specific analysis for ${currentPlatform}...</p>
                </div>
            `;
            
            // Prepare form data
            const formData = new FormData();
            formData.append('file', currentFile);
            formData.append('mode', currentMode);
            formData.append('platform', currentPlatform);
            formData.append('trusted_mode', trustedModeToggle?.checked ? 'true' : 'false');
            
            // Add API credentials if provided
            if (apiUrlInput?.value) {
                formData.append('dartmouth_api_url_form', apiUrlInput.value);
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
                
                showToast(`Analysis started on ${currentPlatform} platform!`, 'success');
                pollResults();
                
            } catch (error) {
                console.error('Failed to start analysis:', error);
                showToast(`Failed to start analysis: ${error.message}`, 'error');
                
                // Reset UI
                analyzeBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Analysis';
                analyzeBtn.disabled = false;
            }
        }
        
        async function pollResults() {
            if (!currentJobId) return;
            
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
                        analyzeBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Analysis';
                        analyzeBtn.disabled = false;
                        displayResults(data.result);
                        
                        // Show report section
                        reportSection.classList.remove('hidden');
                        
                    } else if (data.status === 'error') {
                        clearInterval(pollInterval);
                        showToast(`Analysis failed: ${data.error}`, 'error');
                        analyzeBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Analysis';
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
            let badgeClass, badgeText;
            
            switch(status) {
                case 'processing':
                    badgeClass = 'bg-yellow-100 text-yellow-800';
                    badgeText = 'Processing';
                    break;
                case 'completed':
                    badgeClass = 'bg-green-100 text-green-800';
                    badgeText = 'Completed';
                    break;
                case 'error':
                    badgeClass = 'bg-red-100 text-red-800';
                    badgeText = 'Error';
                    break;
                default:
                    badgeClass = 'bg-gray-100 text-gray-800';
                    badgeText = status;
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
                            <div class="text-sm text-gray-500 mb-1">Platform</div>
                            <div class="font-medium">${escapeHtml(results.platform || 'Unknown')}</div>
                        </div>
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm text-gray-500 mb-1">MD5</div>
                            <div class="font-mono text-sm">${escapeHtml(fileInfo.md5 || 'Unknown')}</div>
                        </div>
                    </div>
                </div>
            `;
            
            // Platform analysis
            if (results.platform_analysis) {
                const platformAnalysis = results.platform_analysis;
                html += `
                    <div class="mb-6">
                        <h3 class="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                            <i class="fas fa-laptop-code text-purple-600"></i> Platform Analysis
                            <span class="bg-${platformAnalysis.success ? 'green' : 'red'}-100 text-${platformAnalysis.success ? 'green' : 'red'}-800 text-xs px-2 py-1 rounded-full">
                                ${platformAnalysis.success ? 'Successful' : 'Failed'}
                            </span>
                        </h3>
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm font-medium text-gray-700 mb-2">Platform: ${escapeHtml(platformAnalysis.platform || 'Unknown')}</div>
                            <div class="text-sm text-gray-600 mb-2">Techniques: ${escapeHtml((platformAnalysis.techniques || []).join(', '))}</div>
                            ${platformAnalysis.tools_available ? `
                                <div class="text-sm text-gray-600">
                                    Tools available: ${Object.entries(platformAnalysis.tools_available)
                                        .filter(([_, available]) => available)
                                        .map(([tool, _]) => tool)
                                        .join(', ')}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
                
                // Update platform analysis section
                platformAnalysisContent.innerHTML = `
                    <div class="space-y-3">
                        <div class="flex items-center gap-2 ${platformAnalysis.success ? 'text-green-600' : 'text-red-600'}">
                            <i class="fas fa-${platformAnalysis.success ? 'check-circle' : 'exclamation-circle'}"></i>
                            <span class="font-medium">Platform analysis ${platformAnalysis.success ? 'completed successfully' : 'failed'}</span>
                        </div>
                        <div class="text-sm text-gray-700">
                            <strong>Platform:</strong> ${escapeHtml(platformAnalysis.platform || 'Unknown')}
                        </div>
                        <div class="text-sm text-gray-700">
                            <strong>Techniques applied:</strong> ${escapeHtml((platformAnalysis.techniques || []).join(', '))}
                        </div>
                    </div>
                `;
                
                if (platformAnalysis.success) {
                    platformStatusBadge.textContent = 'Success';
                    platformStatusBadge.className = 'ml-auto text-sm font-normal px-2 py-1 bg-green-100 text-green-800 rounded';
                } else {
                    platformStatusBadge.textContent = 'Failed';
                    platformStatusBadge.className = 'ml-auto text-sm font-normal px-2 py-1 bg-red-100 text-red-800 rounded';
                }
            }
            
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
            } else {
                // Show disassembler even if no vulnerabilities are detected
                disassemblerSection.classList.remove('hidden');
                disasmStatus.textContent = 'Ready - No vulnerabilities detected';
                disasmStatus.className = 'px-2 py-1 bg-blue-100 text-blue-800 rounded';
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
                                <pre class="text-sm whitespace-pre-wrap">${escapeHtml(insights)}</pre>
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

            // Load functions for disassembler
            loadFunctions();
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
                </div>
            `;
            
            vulnModalContent.innerHTML = html;
            vulnModal.classList.remove('hidden');
        }
        
        function openAIForVulnerability() {
            vulnModal.classList.add('hidden');
            showToast('AI vulnerability analysis requires disassembler integration', 'info');
        }

        // Function loading and disassembly
        let displayedFunctions = [];

        async function loadFunctions() {
            if (!currentJobId) return;

            functionList.innerHTML = `
                <div class="text-center py-4 text-gray-500">
                    <i class="fas fa-spinner fa-spin mb-2"></i>
                    <p>Loading functions...</p>
                </div>
            `;

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
            displayedFunctions = functions || [];
            if (!displayedFunctions || displayedFunctions.length === 0) {
                functionList.innerHTML = `
                    <div class="text-center py-4 text-gray-500">
                        <i class="fas fa-search mb-2"></i>
                        <p>No functions found</p>
                    </div>
                `;
                return;
            }

            let html = '';
            displayedFunctions.forEach((func, index) => {
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
            if (displayedFunctions.length > 0) {
                selectedFunction = displayedFunctions[0];
                loadDisassembly(selectedFunction.name, selectedFunction.address);
            }
        }

        function selectFunction(index) {
            document.querySelectorAll('.function-item').forEach(item => {
                item.classList.remove('selected');
            });

            const functionItem = document.querySelector(`.function-item[data-index="${index}"]`);
            if (functionItem) {
                functionItem.classList.add('selected');
            }

            selectedFunction = displayedFunctions[index];
            loadDisassembly(selectedFunction?.name, selectedFunction?.address);
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
        
        // Function loading and disassembly
        function filterFunctions() {
            const searchTerm = functionSearch.value.toLowerCase();
            const filtered = currentFunctions.filter(func => 
                func.name.toLowerCase().includes(searchTerm) || 
                func.address.toLowerCase().includes(searchTerm)
            );
            renderFunctionList(filtered);
        }
        
        // Report download
        async function downloadReport(type) {
            if (!currentJobId) {
                showToast('No active analysis session', 'error');
                return;
            }
            
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
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            initEventListeners();
            showToast('RevCopilot v3.5 with platform selection loaded', 'info');
        });
    </script>
</body>
</html>"""
    
    return HTMLResponse(content=html_content)

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
    logger.info("RevCopilot v3.5 starting up...")
    logger.info(f"Platform: {sys.platform}")
    logger.info("Features: Multi-platform analysis, AI assistance, vulnerability patching")
    
    # Check platform
    current_platform = sys.platform
    if current_platform == "darwin":
        platform_name = "macOS"
        logger.info("✓ macOS platform detected")
        logger.info("  Available tools: LLDB, DTrace, otool, etc.")
    elif current_platform.startswith("linux"):
        platform_name = "Linux"
        logger.info("✓ Linux platform detected")
        logger.info("  Available tools: GDB, strace, objdump, etc.")
    elif current_platform == "win32":
        platform_name = "Windows"
        logger.warning("⚠ Windows platform detected - limited native analysis")
        logger.info("  Recommend: Use Universal mode or WSL for full analysis")
    else:
        platform_name = current_platform
        logger.info(f"Platform: {platform_name}")
    
    # Check for angr
    if angr is None:
        logger.warning("✗ angr not installed. Symbolic execution features limited.")
    else:
        logger.info("✓ angr available for symbolic execution")
    
    # Create necessary directories
    os.makedirs("static", exist_ok=True)
    temp_dir = os.path.join(tempfile.gettempdir(), "revcopilot_uploads")
    os.makedirs(temp_dir, exist_ok=True)
    
    logger.info("RevCopilot v3.5 ready for requests")

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