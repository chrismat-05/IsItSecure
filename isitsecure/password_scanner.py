"""
Main Password Scanner Class
Orchestrates password analysis and breach checking
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import os

from .password_analyzer import PasswordAnalyzer
from .breach_checker import BreachChecker
from .report_generator import ReportGenerator


class PasswordScanner:
    """
    Main password scanner class that orchestrates analysis and breach checking
    """
    
    def __init__(self):
        self.analyzer = PasswordAnalyzer()
        self.breach_checker = BreachChecker()
        self.report_generator = ReportGenerator()

    def scan_password(self, password: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Scan single password
        
        Args:
            password (str): Password to scan
            options (Dict[str, Any], optional): Scan options
            
        Returns:
            Dict[str, Any]: Scan results
        """
        if options is None:
            options = {}
            
        if not password or not isinstance(password, str):
            raise ValueError('Invalid password input')

        print('Analyzing password strength...')
        analysis = self.analyzer.analyze(password)

        breach_data = {'is_breached': None, 'breach_count': 0, 'risk_level': 'Unknown'}
        
        if options.get('check_breaches', True):
            print('Checking breach databases...')
            breach_data = self.breach_checker.check_breach(password)

        result = {
            'analysis': analysis,
            'breach_data': breach_data,
            'timestamp': datetime.now().isoformat()
        }

        if options.get('format') == 'json':
            return result
        else:
            self.report_generator.generate_console_report(analysis, breach_data)
            return result

    def scan_batch(self, passwords: List[str], options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Scan multiple passwords
        
        Args:
            passwords (List[str]): List of passwords to scan
            options (Dict[str, Any], optional): Scan options
            
        Returns:
            List[Dict[str, Any]]: Batch results
        """
        if options is None:
            options = {}
            
        if not isinstance(passwords, list) or len(passwords) == 0:
            raise ValueError('Invalid passwords array')

        print(f"\nStarting batch analysis of {len(passwords)} passwords...\n")

        results = []
        
        for i, password in enumerate(passwords):
            password = password.strip()
            if not password:
                continue

            print(f"\n[{i + 1}/{len(passwords)}] Processing: {'*' * len(password)}")
            
            try:
                analysis = self.analyzer.analyze(password)
                
                breach_data = {'is_breached': None, 'breach_count': 0, 'risk_level': 'Unknown'}
                if options.get('check_breaches', True):
                    breach_data = self.breach_checker.check_breach(password)

                results.append({
                    'index': i + 1,
                    'analysis': analysis,
                    'breach_data': breach_data,
                    'timestamp': datetime.now().isoformat()
                })

                # Brief status update
                if breach_data.get('is_breached'):
                    status = '🚨 BREACHED'
                elif analysis['score'] >= 80:
                    status = '✅ STRONG'
                elif analysis['score'] >= 60:
                    status = '⚠️ MEDIUM'
                else:
                    status = '❌ WEAK'
                    
                print(f"   Status: {status} | Score: {analysis['score']}/100")

            except Exception as e:
                print(f"❌ Error processing password {i + 1}: {str(e)}")
                results.append({
                    'index': i + 1,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

            # Rate limiting between requests
            if i < len(passwords) - 1 and options.get('check_breaches', True):
                import time
                time.sleep(0.2)  # 200ms delay

        # Generate batch report
        self.report_generator.generate_batch_report(results)

        return results

    def load_passwords_from_file(self, file_path: str) -> List[str]:
        """
        Load passwords from file
        
        Args:
            file_path (str): Path to password file
            
        Returns:
            List[str]: Array of passwords
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
                
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            passwords = [
                line.strip() 
                for line in content.split('\n') 
                if line.strip()
            ]
            
            return passwords
        except Exception as e:
            raise Exception(f"Failed to load passwords from file: {str(e)}")

    def generate_suggestions(self, count: int = 3) -> List[str]:
        """
        Generate password suggestions
        
        Args:
            count (int): Number of suggestions to generate
            
        Returns:
            List[str]: Suggested passwords
        """
        return self.analyzer.generate_passphrase_suggestions(count)