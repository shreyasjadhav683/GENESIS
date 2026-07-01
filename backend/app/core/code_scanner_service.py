import re
import ast
import time
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    type: str = ""
    severity: str = "LOW"           # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str = ""              # injection, xss, auth, crypto, secrets, etc.
    line: int = 0
    column: int = 0
    description: str = ""
    code_snippet: str = ""
    fix_suggestion: str = ""
    cwe_id: str = ""


# ════════════════════════════════════════════════════════════════════════
#  Pattern definitions per language / category
# ════════════════════════════════════════════════════════════════════════

# Generic patterns that apply to MOST languages
GENERIC_PATTERNS: List[Dict[str, Any]] = [
    # ── Secrets & Keys ────────────────────────────────────────────────
    {"pattern": r'''(?:api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']''',
     "type": "Hardcoded API Key", "severity": "HIGH", "category": "secrets",
     "description": "API key hardcoded in source code",
     "fix": "Move to environment variable or secrets manager", "cwe": "CWE-798"},

    {"pattern": r'''(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']''',
     "type": "Hardcoded Password", "severity": "HIGH", "category": "secrets",
     "description": "Password hardcoded in source code",
     "fix": "Use environment variables or a vault service", "cwe": "CWE-798"},

    {"pattern": r'''(?:secret|token|auth)\s*[:=]\s*["\'][A-Za-z0-9_\-/+=]{8,}["\']''',
     "type": "Hardcoded Secret/Token", "severity": "HIGH", "category": "secrets",
     "description": "Secret or token value hardcoded in source",
     "fix": "Use environment variables or secrets manager", "cwe": "CWE-798"},

    {"pattern": r'''AKIA[0-9A-Z]{16}''',
     "type": "AWS Access Key", "severity": "CRITICAL", "category": "secrets",
     "description": "AWS IAM access key ID found in source code",
     "fix": "Remove immediately, rotate key, use IAM roles", "cwe": "CWE-798"},

    {"pattern": r'''(?:-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----)''',
     "type": "Private Key Embedded", "severity": "CRITICAL", "category": "secrets",
     "description": "Private key embedded in source code",
     "fix": "Store keys in secure key management system", "cwe": "CWE-321"},

    {"pattern": r'''(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp)://[^\s"\']+:[^\s"\']+@''',
     "type": "Database Connection String", "severity": "HIGH", "category": "secrets",
     "description": "Database connection string with credentials in source",
     "fix": "Use environment variables for connection strings", "cwe": "CWE-798"},

    # ── Weak Cryptography ─────────────────────────────────────────────
    {"pattern": r'''(?:md5|MD5)\s*\(''',
     "type": "Weak Hash (MD5)", "severity": "MEDIUM", "category": "crypto",
     "description": "MD5 is cryptographically broken; not suitable for security",
     "fix": "Use SHA-256, bcrypt, or argon2 for hashing", "cwe": "CWE-328"},

    {"pattern": r'''(?:sha1|SHA1)\s*\(''',
     "type": "Weak Hash (SHA1)", "severity": "MEDIUM", "category": "crypto",
     "description": "SHA-1 is deprecated and vulnerable to collision attacks",
     "fix": "Use SHA-256 or SHA-3", "cwe": "CWE-328"},

    {"pattern": r'''(?:DES|RC4|RC2|Blowfish)''',
     "type": "Weak Encryption Algorithm", "severity": "HIGH", "category": "crypto",
     "description": "Weak or deprecated encryption algorithm detected",
     "fix": "Use AES-256-GCM or ChaCha20-Poly1305", "cwe": "CWE-327"},

    {"pattern": r'''(?:ECB)''',
     "type": "ECB Mode Encryption", "severity": "HIGH", "category": "crypto",
     "description": "ECB mode does not provide semantic security",
     "fix": "Use CBC, GCM, or CTR mode instead", "cwe": "CWE-327"},

    # ── Network Security ──────────────────────────────────────────────
    {"pattern": r'''http://[^\s"\']+''',
     "type": "HTTP Without TLS", "severity": "MEDIUM", "category": "network",
     "description": "Unencrypted HTTP connection detected",
     "fix": "Use HTTPS for all network connections", "cwe": "CWE-319"},

    {"pattern": r'''verify\s*=\s*False''',
     "type": "SSL Verification Disabled", "severity": "HIGH", "category": "network",
     "description": "SSL certificate verification is disabled",
     "fix": "Enable SSL verification to prevent MITM attacks", "cwe": "CWE-295"},

    {"pattern": r'''CORS.*\*|Access-Control-Allow-Origin.*\*|allow_origins.*\[?\s*["\']\*["\']''',
     "type": "CORS Wildcard", "severity": "MEDIUM", "category": "network",
     "description": "CORS allows all origins — potential security risk",
     "fix": "Restrict CORS to specific trusted domains", "cwe": "CWE-942"},

    # ── Debug / Code Quality ──────────────────────────────────────────
    {"pattern": r'''(?:console\.log|print)\s*\(.*(?:password|secret|token|key|credential)''',
     "type": "Sensitive Data in Logs", "severity": "MEDIUM", "category": "quality",
     "description": "Potentially logging sensitive information",
     "fix": "Remove sensitive data from log/print statements", "cwe": "CWE-532"},

    {"pattern": r'''(?:TODO|FIXME|HACK|XXX).*(?:security|auth|vuln|fix|bypass)''',
     "type": "Security TODO", "severity": "LOW", "category": "quality",
     "description": "Unresolved security-related TODO/FIXME found",
     "fix": "Address the security concern before deploying", "cwe": "CWE-1078"},
]

# Python-specific patterns
PYTHON_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r'''\beval\s*\(''',
     "type": "eval() Usage", "severity": "CRITICAL", "category": "injection",
     "description": "eval() executes arbitrary code — extreme injection risk",
     "fix": "Use ast.literal_eval() or structured parsing", "cwe": "CWE-95"},

    {"pattern": r'''\bexec\s*\(''',
     "type": "exec() Usage", "severity": "CRITICAL", "category": "injection",
     "description": "exec() executes arbitrary code strings",
     "fix": "Avoid exec(); use safe alternatives", "cwe": "CWE-95"},

    {"pattern": r'''subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True''',
     "type": "Command Injection", "severity": "CRITICAL", "category": "injection",
     "description": "subprocess with shell=True is vulnerable to command injection",
     "fix": "Use shell=False and pass args as a list", "cwe": "CWE-78"},

    {"pattern": r'''os\.system\s*\(''',
     "type": "OS Command Execution", "severity": "HIGH", "category": "injection",
     "description": "os.system() is vulnerable to command injection",
     "fix": "Use subprocess.run() with shell=False", "cwe": "CWE-78"},

    {"pattern": r'''os\.popen\s*\(''',
     "type": "OS Pipe Command", "severity": "HIGH", "category": "injection",
     "description": "os.popen() can be exploited for command injection",
     "fix": "Use subprocess.run() with shell=False", "cwe": "CWE-78"},

    {"pattern": r'''import\s+pickle|from\s+pickle\s+import''',
     "type": "Insecure Deserialization (pickle)", "severity": "HIGH", "category": "input_validation",
     "description": "pickle can execute arbitrary code during deserialization",
     "fix": "Use JSON or a safe serialization format", "cwe": "CWE-502"},

    {"pattern": r'''import\s+marshal|from\s+marshal\s+import''',
     "type": "Insecure Deserialization (marshal)", "severity": "HIGH", "category": "input_validation",
     "description": "marshal module is not secure for untrusted data",
     "fix": "Use JSON for serialization", "cwe": "CWE-502"},

    {"pattern": r'''yaml\.load\s*\([^)]*\)(?!.*Loader)''',
     "type": "Unsafe YAML Loading", "severity": "HIGH", "category": "input_validation",
     "description": "yaml.load() without safe Loader can execute arbitrary code",
     "fix": "Use yaml.safe_load() or specify Loader=yaml.SafeLoader", "cwe": "CWE-502"},

    {"pattern": r'''\.format\s*\(.*\)|f["\'].*\{.*\}.*["\']''',
     "type": "Format String (Potential)", "severity": "LOW", "category": "injection",
     "description": "String formatting with user input may enable template injection",
     "fix": "Validate inputs before formatting; avoid f-strings with user data", "cwe": "CWE-134"},

    {"pattern": r'''(?:except\s*:)|(?:except\s+Exception\s*:)''',
     "type": "Broad Exception Handling", "severity": "LOW", "category": "error_handling",
     "description": "Catching all exceptions hides bugs and security issues",
     "fix": "Catch specific exceptions only", "cwe": "CWE-396"},

    {"pattern": r'''(?:except\s*:\s*pass)|(?:except.*:\s*\n\s*pass)''',
     "type": "Silent Error Suppression", "severity": "MEDIUM", "category": "error_handling",
     "description": "Silently ignoring exceptions; errors may go unnoticed",
     "fix": "Log exception details or handle properly", "cwe": "CWE-390"},

    {"pattern": r'''debug\s*=\s*True|DEBUG\s*=\s*True''',
     "type": "Debug Mode Enabled", "severity": "MEDIUM", "category": "quality",
     "description": "Debug mode should be disabled in production",
     "fix": "Set debug=False in production environments", "cwe": "CWE-489"},

    {"pattern": r'''import\s+telnetlib|from\s+telnetlib\s+import''',
     "type": "Insecure Protocol (Telnet)", "severity": "MEDIUM", "category": "network",
     "description": "Telnet transmits data in cleartext",
     "fix": "Use SSH (paramiko) instead of telnet", "cwe": "CWE-319"},

    {"pattern": r'''import\s+ftplib|from\s+ftplib\s+import''',
     "type": "Insecure Protocol (FTP)", "severity": "MEDIUM", "category": "network",
     "description": "FTP transmits credentials in cleartext",
     "fix": "Use SFTP or FTPS instead", "cwe": "CWE-319"},

    {"pattern": r'''random\.\w+\(|import\s+random''',
     "type": "Weak Random Number Generator", "severity": "MEDIUM", "category": "crypto",
     "description": "Python's random module is not cryptographically secure",
     "fix": "Use secrets module for security-sensitive randomness", "cwe": "CWE-338"},

    {"pattern": r'''open\s*\(.*["\']w["\']|open\s*\(.*["\']a["\']''',
     "type": "File Write Operation", "severity": "LOW", "category": "file_ops",
     "description": "File write detected — ensure path is validated",
     "fix": "Validate/sanitize file paths; use safe directory", "cwe": "CWE-73"},

    {"pattern": r'''os\.path\.join\s*\(.*request|os\.path\.join\s*\(.*input''',
     "type": "Path Traversal Risk", "severity": "HIGH", "category": "file_ops",
     "description": "User input in file path may allow path traversal",
     "fix": "Use os.path.realpath() and validate against base directory", "cwe": "CWE-22"},

    {"pattern": r'''__import__\s*\(''',
     "type": "Dynamic Import", "severity": "MEDIUM", "category": "injection",
     "description": "__import__() with user input enables arbitrary module loading",
     "fix": "Use explicit imports; validate module names", "cwe": "CWE-95"},

    {"pattern": r'''render_template_string\s*\(''',
     "type": "Server-Side Template Injection", "severity": "CRITICAL", "category": "injection",
     "description": "render_template_string() with user input enables SSTI",
     "fix": "Use render_template() with separate template files", "cwe": "CWE-1336"},

    {"pattern": r'''\.execute\s*\([^)]*%|\.execute\s*\([^)]*\.format|\.execute\s*\([^)]*f["\']''',
     "type": "SQL Injection", "severity": "CRITICAL", "category": "injection",
     "description": "SQL query built with string formatting — injection risk",
     "fix": "Use parameterized queries with placeholders (?)", "cwe": "CWE-89"},

    {"pattern": r'''request\.args\.get|request\.form\.get|request\.json''',
     "type": "Unsanitized User Input", "severity": "LOW", "category": "input_validation",
     "description": "User input accessed — ensure proper validation",
     "fix": "Validate and sanitize all user inputs", "cwe": "CWE-20"},
]

# JavaScript / TypeScript patterns
JS_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r'''\beval\s*\(''',
     "type": "eval() Usage", "severity": "CRITICAL", "category": "injection",
     "description": "eval() executes arbitrary JavaScript — extreme XSS risk",
     "fix": "Use JSON.parse() or safe alternatives", "cwe": "CWE-95"},

    {"pattern": r'''\.innerHTML\s*=''',
     "type": "innerHTML Assignment", "severity": "HIGH", "category": "xss",
     "description": "Direct innerHTML assignment can introduce XSS",
     "fix": "Use textContent or DOMPurify.sanitize()", "cwe": "CWE-79"},

    {"pattern": r'''document\.write\s*\(''',
     "type": "document.write()", "severity": "HIGH", "category": "xss",
     "description": "document.write() can inject malicious HTML",
     "fix": "Use DOM manipulation methods (createElement, appendChild)", "cwe": "CWE-79"},

    {"pattern": r'''dangerouslySetInnerHTML''',
     "type": "dangerouslySetInnerHTML", "severity": "HIGH", "category": "xss",
     "description": "React's dangerouslySetInnerHTML bypasses XSS protection",
     "fix": "Sanitize HTML with DOMPurify before rendering", "cwe": "CWE-79"},

    {"pattern": r'''new\s+Function\s*\(''',
     "type": "Dynamic Function Construction", "severity": "HIGH", "category": "injection",
     "description": "new Function() is equivalent to eval()",
     "fix": "Avoid dynamic function construction", "cwe": "CWE-95"},

    {"pattern": r'''setTimeout\s*\(\s*["\']|setInterval\s*\(\s*["\']''',
     "type": "String in setTimeout/setInterval", "severity": "MEDIUM", "category": "injection",
     "description": "Passing strings to timer functions acts like eval()",
     "fix": "Pass function references instead of strings", "cwe": "CWE-95"},

    {"pattern": r'''(?:child_process|execSync|spawnSync)\s*[\.(]''',
     "type": "Command Execution", "severity": "HIGH", "category": "injection",
     "description": "Shell command execution detected",
     "fix": "Validate/sanitize inputs; avoid shell execution", "cwe": "CWE-78"},

    {"pattern": r'''require\s*\(\s*[^"\'`]''',
     "type": "Dynamic Require", "severity": "MEDIUM", "category": "injection",
     "description": "Dynamic require() with variable path",
     "fix": "Use static require paths; validate dynamic paths", "cwe": "CWE-95"},

    {"pattern": r'''document\.cookie''',
     "type": "Cookie Access", "severity": "MEDIUM", "category": "xss",
     "description": "Direct cookie access — ensure HttpOnly flag is set",
     "fix": "Use HttpOnly cookies; access via backend only", "cwe": "CWE-1004"},

    {"pattern": r'''localStorage\.setItem\s*\(.*(?:token|jwt|session|auth)''',
     "type": "Sensitive Data in localStorage", "severity": "MEDIUM", "category": "secrets",
     "description": "Storing auth tokens in localStorage is vulnerable to XSS",
     "fix": "Use HttpOnly cookies for authentication tokens", "cwe": "CWE-922"},

    {"pattern": r'''Math\.random\s*\(''',
     "type": "Weak Random (Math.random)", "severity": "MEDIUM", "category": "crypto",
     "description": "Math.random() is not cryptographically secure",
     "fix": "Use crypto.getRandomValues() or crypto.randomUUID()", "cwe": "CWE-338"},

    {"pattern": r'''atob\s*\(|btoa\s*\(''',
     "type": "Base64 as Encryption", "severity": "LOW", "category": "crypto",
     "description": "Base64 is encoding, not encryption — provides no security",
     "fix": "Use proper encryption (AES, RSA) for sensitive data", "cwe": "CWE-261"},

    {"pattern": r'''res\.send\s*\(.*err|res\.json\s*\(.*error.*stack''',
     "type": "Error Details Exposed", "severity": "MEDIUM", "category": "error_handling",
     "description": "Stack traces or error details sent to client",
     "fix": "Send generic error messages to client; log details server-side", "cwe": "CWE-209"},

    {"pattern": r'''(?:catch\s*\(\s*\w*\s*\)\s*\{\s*\})|(?:catch\s*\{[\s\n]*\})''',
     "type": "Empty Catch Block", "severity": "LOW", "category": "error_handling",
     "description": "Empty catch block silently swallows errors",
     "fix": "Log errors or handle them properly", "cwe": "CWE-390"},

    {"pattern": r'''process\.env\.\w+.*\|\|.*["\'][^"\']{4,}["\']''',
     "type": "Fallback Secret Value", "severity": "MEDIUM", "category": "secrets",
     "description": "Fallback hardcoded value for environment variable",
     "fix": "Fail fast if env vars are missing; don't use fallback secrets", "cwe": "CWE-798"},
]

# Java patterns
JAVA_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r'''Runtime\.getRuntime\(\)\.exec\s*\(''',
     "type": "OS Command Execution", "severity": "CRITICAL", "category": "injection",
     "description": "Runtime.exec() executes shell commands",
     "fix": "Use ProcessBuilder with argument list", "cwe": "CWE-78"},

    {"pattern": r'''Statement.*execute(?:Query|Update)?\s*\([^)]*\+''',
     "type": "SQL Injection", "severity": "CRITICAL", "category": "injection",
     "description": "SQL query built with string concatenation",
     "fix": "Use PreparedStatement with parameterized queries", "cwe": "CWE-89"},

    {"pattern": r'''ObjectInputStream\s*\(''',
     "type": "Insecure Deserialization", "severity": "HIGH", "category": "input_validation",
     "description": "ObjectInputStream can execute arbitrary code",
     "fix": "Validate/filter serialized objects; use JSON", "cwe": "CWE-502"},

    {"pattern": r'''new\s+Random\s*\(''',
     "type": "Weak Random (java.util.Random)", "severity": "MEDIUM", "category": "crypto",
     "description": "java.util.Random is not cryptographically secure",
     "fix": "Use java.security.SecureRandom", "cwe": "CWE-338"},

    {"pattern": r'''e\.printStackTrace\s*\(''',
     "type": "Stack Trace Exposure", "severity": "LOW", "category": "error_handling",
     "description": "Stack traces may leak implementation details",
     "fix": "Use proper logging framework", "cwe": "CWE-209"},

    {"pattern": r'''catch\s*\(\s*Exception\s''',
     "type": "Broad Exception Catch", "severity": "LOW", "category": "error_handling",
     "description": "Catching generic Exception hides specific errors",
     "fix": "Catch specific exception types", "cwe": "CWE-396"},
]

# C/C++ patterns
C_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r'''\bgets\s*\(''',
     "type": "Buffer Overflow (gets)", "severity": "CRITICAL", "category": "injection",
     "description": "gets() has no bounds checking — buffer overflow guaranteed",
     "fix": "Use fgets() with size limit", "cwe": "CWE-120"},

    {"pattern": r'''\bstrcpy\s*\(''',
     "type": "Buffer Overflow (strcpy)", "severity": "HIGH", "category": "injection",
     "description": "strcpy() has no bounds checking",
     "fix": "Use strncpy() or strlcpy() with size limit", "cwe": "CWE-120"},

    {"pattern": r'''\bstrcat\s*\(''',
     "type": "Buffer Overflow (strcat)", "severity": "HIGH", "category": "injection",
     "description": "strcat() has no bounds checking",
     "fix": "Use strncat() with size limit", "cwe": "CWE-120"},

    {"pattern": r'''\bsprintf\s*\(''',
     "type": "Buffer Overflow (sprintf)", "severity": "HIGH", "category": "injection",
     "description": "sprintf() can overflow buffer",
     "fix": "Use snprintf() with size limit", "cwe": "CWE-120"},

    {"pattern": r'''printf\s*\([^"]+\)(?!.*%)''',
     "type": "Format String Vulnerability", "severity": "HIGH", "category": "injection",
     "description": "Uncontrolled format string",
     "fix": "Always use format specifier: printf(\"%s\", str)", "cwe": "CWE-134"},

    {"pattern": r'''\bmalloc\s*\((?!.*free)''',
     "type": "Potential Memory Leak", "severity": "MEDIUM", "category": "quality",
     "description": "malloc() without corresponding free()",
     "fix": "Ensure all allocated memory is freed", "cwe": "CWE-401"},

    {"pattern": r'''system\s*\(''',
     "type": "OS Command Execution", "severity": "HIGH", "category": "injection",
     "description": "system() executes shell commands",
     "fix": "Use exec*() family; avoid shell commands", "cwe": "CWE-78"},

    {"pattern": r'''\bfree\s*\([^)]+\).*\bfree\s*\(\1\)''',
     "type": "Double Free", "severity": "HIGH", "category": "quality",
     "description": "Freeing memory twice causes undefined behavior",
     "fix": "Set pointer to NULL after free()", "cwe": "CWE-415"},
]

# PHP patterns
PHP_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r'''\beval\s*\(''',
     "type": "eval() Usage", "severity": "CRITICAL", "category": "injection",
     "description": "eval() executes arbitrary PHP code",
     "fix": "Avoid eval(); use structured alternatives", "cwe": "CWE-95"},

    {"pattern": r'''\$_(?:GET|POST|REQUEST|COOKIE)\s*\[''',
     "type": "Direct Superglobal Access", "severity": "MEDIUM", "category": "input_validation",
     "description": "Direct access to user-supplied data without sanitization",
     "fix": "Use filter_input() or validated/sanitized input", "cwe": "CWE-20"},

    {"pattern": r'''mysql_query\s*\(|mysqli_query\s*\([^)]*\$''',
     "type": "SQL Injection", "severity": "CRITICAL", "category": "injection",
     "description": "SQL query with unsanitized variable interpolation",
     "fix": "Use prepared statements with PDO or MySQLi", "cwe": "CWE-89"},

    {"pattern": r'''shell_exec\s*\(|passthru\s*\(|system\s*\(|exec\s*\(|popen\s*\(''',
     "type": "Command Injection", "severity": "CRITICAL", "category": "injection",
     "description": "Shell execution function detected",
     "fix": "Use escapeshellarg(); avoid shell execution", "cwe": "CWE-78"},

    {"pattern": r'''include\s*\(\s*\$|require\s*\(\s*\$''',
     "type": "File Inclusion (LFI/RFI)", "severity": "CRITICAL", "category": "injection",
     "description": "Dynamic file inclusion with user input",
     "fix": "Use whitelist for included files", "cwe": "CWE-98"},

    {"pattern": r'''echo\s+\$_|print\s+\$_''',
     "type": "Reflected XSS", "severity": "HIGH", "category": "xss",
     "description": "Outputting user input without escaping",
     "fix": "Use htmlspecialchars() for output", "cwe": "CWE-79"},

    {"pattern": r'''extract\s*\(\s*\$_''',
     "type": "Variable Injection (extract)", "severity": "HIGH", "category": "injection",
     "description": "extract() on user input creates arbitrary variables",
     "fix": "Avoid extract(); access array keys directly", "cwe": "CWE-621"},
]

# Go patterns
GO_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r'''exec\.Command\s*\(''',
     "type": "Command Execution", "severity": "HIGH", "category": "injection",
     "description": "OS command execution detected",
     "fix": "Validate all input; avoid shell commands", "cwe": "CWE-78"},

    {"pattern": r'''fmt\.Sprintf\s*\([^)]*%.*\+''',
     "type": "SQL Injection via Sprintf", "severity": "HIGH", "category": "injection",
     "description": "Building SQL query with Sprintf",
     "fix": "Use parameterized queries with database/sql", "cwe": "CWE-89"},

    {"pattern": r'''http\.ListenAndServe\s*\(''',
     "type": "HTTP Without TLS", "severity": "MEDIUM", "category": "network",
     "description": "HTTP server without TLS encryption",
     "fix": "Use http.ListenAndServeTLS()", "cwe": "CWE-319"},

    {"pattern": r'''template\.HTML\s*\(''',
     "type": "Unescaped HTML Template", "severity": "HIGH", "category": "xss",
     "description": "template.HTML marks string as safe — XSS risk",
     "fix": "Validate input before marking as template.HTML", "cwe": "CWE-79"},
]

# Ruby patterns
RUBY_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r'''\beval\s*[\("]''',
     "type": "eval() Usage", "severity": "CRITICAL", "category": "injection",
     "description": "eval() executes arbitrary Ruby code",
     "fix": "Avoid eval(); use safe alternatives", "cwe": "CWE-95"},

    {"pattern": r'''system\s*\(|`[^`]*`|%x\{''',
     "type": "Command Execution", "severity": "HIGH", "category": "injection",
     "description": "Shell command execution detected",
     "fix": "Use Open3; validate all inputs", "cwe": "CWE-78"},

    {"pattern": r'''\.html_safe''',
     "type": "XSS via html_safe", "severity": "HIGH", "category": "xss",
     "description": "html_safe bypasses Rails XSS protection",
     "fix": "Use sanitize() helper instead", "cwe": "CWE-79"},

    {"pattern": r'''Marshal\.load\s*\(''',
     "type": "Insecure Deserialization", "severity": "HIGH", "category": "input_validation",
     "description": "Marshal.load can execute arbitrary code",
     "fix": "Use JSON for untrusted data", "cwe": "CWE-502"},
]

LANGUAGE_PATTERNS = {
    "python": PYTHON_PATTERNS,
    "javascript": JS_PATTERNS,
    "typescript": JS_PATTERNS,
    "java": JAVA_PATTERNS,
    "c": C_PATTERNS,
    "cpp": C_PATTERNS,
    "php": PHP_PATTERNS,
    "go": GO_PATTERNS,
    "ruby": RUBY_PATTERNS,
}


class CodeAnalyzerService:
    """Multi-language, multi-category SAST (Static Application Security Testing) engine."""

    def detect_language(self, code: str, filename: str = "") -> str:
        """Auto-detect language from filename extension or code content."""
        ext_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
            '.jsx': 'javascript', '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.h': 'c',
            '.hpp': 'cpp', '.php': 'php', '.go': 'go', '.rb': 'ruby', '.rs': 'rust',
        }
        if filename:
            for ext, lang in ext_map.items():
                if filename.lower().endswith(ext):
                    return lang

        # Content-based detection
        if re.search(r'^import\s+\w+|^from\s+\w+\s+import|def\s+\w+\s*\(.*\)\s*:', code, re.MULTILINE):
            return 'python'
        if re.search(r'(?:const|let|var|function)\s+\w+|require\s*\(|import\s+.*from', code, re.MULTILINE):
            return 'javascript'
        if re.search(r'public\s+(?:class|static\s+void\s+main)', code, re.MULTILINE):
            return 'java'
        if re.search(r'#include\s*<|int\s+main\s*\(', code, re.MULTILINE):
            return 'c'
        if re.search(r'<\?php', code, re.MULTILINE):
            return 'php'
        if re.search(r'package\s+main|func\s+\w+\s*\(', code, re.MULTILINE):
            return 'go'
        if re.search(r'(?:require|puts|def\s+\w+$)', code, re.MULTILINE):
            return 'ruby'

        return 'unknown'

    def analyze(self, code: str, language: str = "", filename: str = "") -> dict:
        """Run full SAST analysis on the provided code."""
        start_time = time.time()

        if not language or language == 'auto':
            language = self.detect_language(code, filename)

        lines = code.split('\n')
        line_count = len(lines)

        vulnerabilities: List[Dict[str, Any]] = []
        scan_modules = []

        # ── Phase 1: Language-specific patterns ──────────────────────────
        phase_start = time.time()
        lang_patterns = LANGUAGE_PATTERNS.get(language, [])
        if lang_patterns:
            self._scan_patterns(code, lines, lang_patterns, vulnerabilities)
            scan_modules.append({"name": f"{language.title()} Patterns", "status": "done",
                                  "checks": len(lang_patterns),
                                  "time_ms": int((time.time() - phase_start) * 1000)})

        # ── Phase 2: Generic patterns ────────────────────────────────────
        phase_start = time.time()
        self._scan_patterns(code, lines, GENERIC_PATTERNS, vulnerabilities)
        scan_modules.append({"name": "Generic Patterns", "status": "done",
                              "checks": len(GENERIC_PATTERNS),
                              "time_ms": int((time.time() - phase_start) * 1000)})

        # ── Phase 3: Python AST analysis (if Python) ─────────────────────
        if language == 'python':
            phase_start = time.time()
            try:
                ast_issues = self._python_ast_analysis(code)
                # Deduplicate with regex findings
                existing_types = {v["type"] for v in vulnerabilities}
                for issue in ast_issues:
                    if issue["type"] not in existing_types:
                        vulnerabilities.append(issue)
                scan_modules.append({"name": "Python AST Analysis", "status": "done",
                                      "checks": "deep",
                                      "time_ms": int((time.time() - phase_start) * 1000)})
            except Exception as e:
                scan_modules.append({"name": "Python AST Analysis", "status": "error",
                                      "error": str(e)[:60],
                                      "time_ms": int((time.time() - phase_start) * 1000)})

        # ── Phase 4: Entropy analysis for secrets ────────────────────────
        phase_start = time.time()
        self._entropy_analysis(code, lines, vulnerabilities)
        scan_modules.append({"name": "Entropy Analysis", "status": "done",
                              "time_ms": int((time.time() - phase_start) * 1000)})

        # ── Phase 5: Complexity & metrics ────────────────────────────────
        phase_start = time.time()
        metrics = self._code_metrics(code, lines, language)
        scan_modules.append({"name": "Code Metrics", "status": "done",
                              "time_ms": int((time.time() - phase_start) * 1000)})

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        vulnerabilities.sort(key=lambda v: severity_order.get(v.get("severity", "LOW"), 4))

        # Deduplicate same type + same line
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            key = (v["type"], v.get("line", 0))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        vulnerabilities = unique_vulns

        # Calculate risk
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        risk_score = 0
        for v in vulnerabilities:
            sev = v.get("severity", "LOW").lower()
            summary[sev] = summary.get(sev, 0) + 1
            risk_score += {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}.get(sev, 0)

        risk_score = min(risk_score, 100)

        if risk_score >= 75:
            risk_level = "CRITICAL"
            grade = "F"
        elif risk_score >= 50:
            risk_level = "HIGH"
            grade = "D"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
            grade = "C"
        elif risk_score >= 10:
            risk_level = "LOW"
            grade = "B"
        else:
            risk_level = "SECURE"
            grade = "A"

        total_time = int((time.time() - start_time) * 1000)

        return {
            "filename": filename or "snippet",
            "language": language,
            "lines_analyzed": line_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "grade": grade,
            "summary": summary,
            "vulnerabilities": vulnerabilities,
            "scan_modules": scan_modules,
            "metrics": metrics,
            "scan_time_ms": total_time,
        }

    def _scan_patterns(self, code: str, lines: List[str], patterns: List[Dict], vulns: List[Dict]):
        """Scan code against regex pattern list."""
        for pat_def in patterns:
            try:
                for match in re.finditer(pat_def["pattern"], code, re.IGNORECASE | re.MULTILINE):
                    # Find line number
                    pos = match.start()
                    line_num = code[:pos].count('\n') + 1
                    # Get code snippet
                    line_idx = line_num - 1
                    snippet = lines[line_idx].strip() if 0 <= line_idx < len(lines) else ""

                    vulns.append({
                        "type": pat_def["type"],
                        "severity": pat_def["severity"],
                        "category": pat_def["category"],
                        "line": line_num,
                        "column": match.start() - code.rfind('\n', 0, match.start()),
                        "description": pat_def["description"],
                        "code_snippet": snippet[:120],
                        "fix_suggestion": pat_def.get("fix", ""),
                        "cwe_id": pat_def.get("cwe", ""),
                    })
            except re.error:
                continue

    def _python_ast_analysis(self, code: str) -> List[Dict]:
        """Deep Python analysis using AST."""
        issues = []
        tree = ast.parse(code)

        class DeepVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                # Detect dangerous built-in functions
                if isinstance(node.func, ast.Name):
                    if node.func.id == 'compile':
                        issues.append({
                            "type": "compile() Usage", "severity": "HIGH", "category": "injection",
                            "line": node.lineno, "description": "compile() can compile arbitrary code",
                            "code_snippet": "", "fix_suggestion": "Avoid compile() with user input",
                            "cwe_id": "CWE-95"
                        })
                    elif node.func.id == 'globals':
                        issues.append({
                            "type": "globals() Access", "severity": "MEDIUM", "category": "quality",
                            "line": node.lineno, "description": "globals() exposes all global variables",
                            "code_snippet": "", "fix_suggestion": "Avoid globals(); use explicit parameters",
                            "cwe_id": "CWE-749"
                        })

                # Method calls
                if isinstance(node.func, ast.Attribute):
                    # Detect insecure tempfile usage
                    if node.func.attr == 'mktemp':
                        issues.append({
                            "type": "Insecure Temp File", "severity": "MEDIUM", "category": "file_ops",
                            "line": node.lineno, "description": "mktemp() is vulnerable to race conditions",
                            "code_snippet": "", "fix_suggestion": "Use tempfile.mkstemp() instead",
                            "cwe_id": "CWE-377"
                        })
                    # os.chmod with permissive modes
                    if node.func.attr == 'chmod' and len(node.args) >= 2:
                        if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, int):
                            mode = node.args[1].value
                            if mode & 0o777 == 0o777:
                                issues.append({
                                    "type": "Insecure File Permissions", "severity": "MEDIUM", "category": "file_ops",
                                    "line": node.lineno, "description": "File set to world-writable (777)",
                                    "code_snippet": "", "fix_suggestion": "Use restrictive permissions (e.g., 0o600)",
                                    "cwe_id": "CWE-732"
                                })

                self.generic_visit(node)

            def visit_Assert(self, node):
                issues.append({
                    "type": "Assert in Production", "severity": "LOW", "category": "quality",
                    "line": node.lineno, "description": "assert statements are removed with -O flag — don't use for security",
                    "code_snippet": "", "fix_suggestion": "Use explicit if/raise for security checks",
                    "cwe_id": "CWE-617"
                })
                self.generic_visit(node)

        DeepVisitor().visit(tree)
        return issues

    def _entropy_analysis(self, code: str, lines: List[str], vulns: List[Dict]):
        """Detect high-entropy strings that might be secrets."""
        import math
        # Find quoted strings that are long and high-entropy
        for i, line in enumerate(lines, 1):
            for match in re.finditer(r'''["\']([A-Za-z0-9+/=_\-]{20,})["\']''', line):
                s = match.group(1)
                if len(s) < 20:
                    continue
                # Calculate entropy
                freq = {}
                for c in s:
                    freq[c] = freq.get(c, 0) + 1
                entropy = -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())
                if entropy > 4.5 and len(s) >= 24:
                    # Check not already caught by other rules
                    vulns.append({
                        "type": "High-Entropy String",
                        "severity": "MEDIUM",
                        "category": "secrets",
                        "line": i,
                        "description": f"High-entropy string ({entropy:.1f} bits) — possible embedded secret",
                        "code_snippet": line.strip()[:100],
                        "fix_suggestion": "If this is a secret, move to environment variables",
                        "cwe_id": "CWE-798",
                    })

    def _code_metrics(self, code: str, lines: List[str], language: str) -> Dict:
        """Calculate basic code quality metrics."""
        total_lines = len(lines)
        blank_lines = sum(1 for l in lines if not l.strip())
        comment_lines = 0
        if language in ('python', 'ruby'):
            comment_lines = sum(1 for l in lines if l.strip().startswith('#'))
        elif language in ('javascript', 'typescript', 'java', 'c', 'cpp', 'go', 'php'):
            comment_lines = sum(1 for l in lines if l.strip().startswith('//'))
        code_lines = total_lines - blank_lines - comment_lines

        # Longest line
        max_line = max((len(l) for l in lines), default=0)

        # Function count (rough)
        if language == 'python':
            func_count = len(re.findall(r'^\s*def\s+\w+', code, re.MULTILINE))
            class_count = len(re.findall(r'^\s*class\s+\w+', code, re.MULTILINE))
        elif language in ('javascript', 'typescript'):
            func_count = len(re.findall(r'(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>)', code, re.MULTILINE))
            class_count = len(re.findall(r'class\s+\w+', code, re.MULTILINE))
        elif language == 'java':
            func_count = len(re.findall(r'(?:public|private|protected)\s+\w+\s+\w+\s*\(', code, re.MULTILINE))
            class_count = len(re.findall(r'class\s+\w+', code, re.MULTILINE))
        else:
            func_count = 0
            class_count = 0

        return {
            "total_lines": total_lines,
            "code_lines": code_lines,
            "blank_lines": blank_lines,
            "comment_lines": comment_lines,
            "max_line_length": max_line,
            "functions": func_count,
            "classes": class_count,
            "comment_ratio": round(comment_lines / max(code_lines, 1) * 100, 1),
        }


code_analyzer = CodeAnalyzerService()
