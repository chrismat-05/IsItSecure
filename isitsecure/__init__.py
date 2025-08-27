"""
IsItSecure? - Secure Password Health Scanner

A comprehensive password security scanner that analyzes password strength
and checks breach exposure using privacy-preserving techniques.
"""

from .password_scanner import PasswordScanner
from .password_analyzer import PasswordAnalyzer
from .breach_checker import BreachChecker
from .report_generator import ReportGenerator

__version__ = "1.0.0"
__author__ = "Chris Mathew Aje"
__email__ = "chrismaje63@gmail.com"

__all__ = [
    "PasswordScanner",
    "PasswordAnalyzer", 
    "BreachChecker",
    "ReportGenerator"
]