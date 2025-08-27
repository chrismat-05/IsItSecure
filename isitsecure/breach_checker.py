"""
Breach Database Checker
Uses HaveIBeenPwned API with k-anonymity for privacy
"""

import hashlib
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any


class BreachChecker:
    """
    Breach database checker using HaveIBeenPwned API
    """
    
    def __init__(self):
        self.hibp_api_url = 'https://api.pwnedpasswords.com/range'
        self.user_agent = 'IsItSecure-Password-Scanner-v1.0'

    def check_breach(self, password: str) -> Dict[str, Any]:
        """
        Check if password appears in known breaches
        
        Args:
            password (str): Password to check
            
        Returns:
            Dict[str, Any]: Breach information
        """
        try:
            sha1_hash = self._hash_password(password)
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:].lower()

            request = urllib.request.Request(
                f"{self.hibp_api_url}/{prefix}",
                headers={'User-Agent': self.user_agent}
            )
            
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status == 200:
                    data = response.read().decode('utf-8')
                    breach_count = self._parse_breach_response(data, suffix)
                    
                    return {
                        'is_breached': breach_count > 0,
                        'breach_count': breach_count,
                        'risk_level': self._determine_breach_risk(breach_count)
                    }
                else:
                    raise urllib.error.HTTPError(
                        response.url, response.status, 
                        f"API request failed: {response.status}", 
                        response.headers, None
                    )

        except urllib.error.HTTPError as e:
            if e.code == 429:
                error_msg = 'Rate limit exceeded. Please wait before retrying.'
            else:
                error_msg = f'API request failed: {e.code}'
        except urllib.error.URLError as e:
            error_msg = f'Network error: {str(e)}'
        except Exception as e:
            error_msg = f'Unexpected error: {str(e)}'

        print(f'Warning: Breach check failed: {error_msg}')
        return {
            'is_breached': None,
            'breach_count': 0,
            'risk_level': 'Unknown',
            'error': error_msg
        }

    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-1 for k-anonymity"""
        return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    def _parse_breach_response(self, response_data: str, suffix: str) -> int:
        """Parse HIBP API response"""
        lines = response_data.strip().split('\n')
        
        for line in lines:
            if ':' in line:
                hash_suffix, count = line.split(':', 1)
                if hash_suffix.lower() == suffix:
                    return int(count)

        return 0

    def _determine_breach_risk(self, breach_count: int) -> str:
        """Determine breach risk level"""
        if breach_count == 0:
            return 'Safe'
        elif breach_count < 10:
            return 'Low'
        elif breach_count < 100:
            return 'Medium'
        elif breach_count < 1000:
            return 'High'
        else:
            return 'Critical'

    def batch_check(self, passwords: List[str]) -> List[Dict[str, Any]]:
        """
        Batch check multiple passwords
        
        Args:
            passwords (List[str]): List of passwords to check
            
        Returns:
            List[Dict[str, Any]]: Batch results
        """
        results = []
        
        for i, password in enumerate(passwords):
            print(f"Checking breach status: {i + 1}/{len(passwords)}")
            
            breach_result = self.check_breach(password)
            results.append({
                'index': i,
                'password': password,
                **breach_result
            })

            # Rate limiting: wait between requests
            if i < len(passwords) - 1:
                import time
                time.sleep(0.1)  # 100ms delay

        return results