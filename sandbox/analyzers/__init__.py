"""SentinelForge sandbox analyzers.

Static analysis only: artifacts are parsed as text in this isolated module.
The analyzer NEVER executes sample content - see docs/security-model.md.
"""

from .powershell_analyzer import analyze_powershell_file, analyze_powershell_text

__all__ = ["analyze_powershell_file", "analyze_powershell_text"]
