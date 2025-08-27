"""
Password Analysis Module
Analyzes password strength, complexity, and common weaknesses
"""

import re
import math
import string
from typing import Dict, List, Set, Any


class PasswordAnalyzer:
    """
    Comprehensive password strength analyzer
    """
    
    def __init__(self):
        self.common_passwords: Set[str] = {
            'password', '123456', '123456789', 'qwerty', 'abc123', 'monkey',
            'letmein', 'dragon', '111111', 'baseball', 'iloveyou', 'trustno1',
            'admin', 'welcome', 'sunshine', 'princess', 'football', 'charlie',
            'aa123456', 'password1', '1234567890', 'master', 'hello', 'login',
            'passw0rd', 'password123', 'admin123', 'root', 'toor', 'pass',
            'test', 'guest', 'info', 'adm', 'mysql', 'user', 'administrator'
        }
        
        self.common_patterns: List[re.Pattern] = [
            re.compile(r'^(.)\1{3,}$'),  # Repeated characters
            re.compile(r'^(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)'),  # Sequential numbers
            re.compile(r'^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', re.IGNORECASE),  # Sequential letters
            re.compile(r'^(.{1,3})\1+$'),  # Simple repetitions
            re.compile(r'(19|20)\d{2}$'),  # Years at end
            re.compile(r'^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)', re.IGNORECASE),  # Months
            re.compile(r'(monday|tuesday|wednesday|thursday|friday|saturday|sunday)', re.IGNORECASE)  # Days of week
        ]

    def analyze(self, password: str) -> Dict[str, Any]:
        """
        Comprehensive password analysis
        
        Args:
            password (str): The password to analyze
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
            
        analysis = {
            'password': password,
            'length': len(password),
            'strength': self._calculate_strength(password),
            'entropy': self._calculate_entropy(password),
            'composition': self._analyze_composition(password),
            'weaknesses': self._find_weaknesses(password),
            'suggestions': []
        }

        analysis['score'] = self._calculate_score(analysis)
        analysis['risk_level'] = self._determine_risk_level(analysis['score'])
        analysis['suggestions'] = self._generate_suggestions(analysis)

        return analysis

    def _calculate_strength(self, password: str) -> Dict[str, Any]:
        """Calculate password strength components"""
        return {
            'length': self._evaluate_length(password),
            'complexity': self._evaluate_complexity(password),
            'uniqueness': self._evaluate_uniqueness(password)
        }

    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy (randomness measure)
        
        Args:
            password (str): Password to analyze
            
        Returns:
            float: Entropy in bits
        """
        char_sets = {
            'lowercase': bool(re.search(r'[a-z]', password)),
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'digits': bool(re.search(r'[0-9]', password)),
            'symbols': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?~`]', password))
        }

        charset_size = 0
        if char_sets['lowercase']:
            charset_size += 26
        if char_sets['uppercase']:
            charset_size += 26
        if char_sets['digits']:
            charset_size += 10
        if char_sets['symbols']:
            charset_size += 32

        if charset_size == 0:
            return 0.0

        return math.log2(charset_size ** len(password))

    def _analyze_composition(self, password: str) -> Dict[str, Any]:
        """Analyze password composition"""
        lowercase_matches = re.findall(r'[a-z]', password)
        uppercase_matches = re.findall(r'[A-Z]', password)
        digit_matches = re.findall(r'[0-9]', password)
        symbol_matches = re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?~`]', password)
        space_matches = re.findall(r'\s', password)

        return {
            'has_lowercase': len(lowercase_matches) > 0,
            'has_uppercase': len(uppercase_matches) > 0,
            'has_digits': len(digit_matches) > 0,
            'has_symbols': len(symbol_matches) > 0,
            'has_spaces': len(space_matches) > 0,
            'lowercase_count': len(lowercase_matches),
            'uppercase_count': len(uppercase_matches),
            'digit_count': len(digit_matches),
            'symbol_count': len(symbol_matches)
        }

    def _find_weaknesses(self, password: str) -> List[str]:
        """Find password weaknesses"""
        weaknesses = []

        if len(password) < 8:
            weaknesses.append('Too short (less than 8 characters)')

        if password.lower() in self.common_passwords:
            weaknesses.append('Common password found in dictionary')

        for pattern in self.common_patterns:
            if pattern.search(password):
                weaknesses.append('Contains predictable pattern')
                break

        composition = self._analyze_composition(password)
        if not composition['has_lowercase'] and not composition['has_uppercase']:
            weaknesses.append('Missing letter characters')
        if not composition['has_digits']:
            weaknesses.append('No numbers included')
        if not composition['has_symbols']:
            weaknesses.append('No special characters')

        if self._has_keyboard_pattern(password):
            weaknesses.append('Contains keyboard pattern (e.g., qwerty, 12345)')

        if self._has_personal_info_pattern(password):
            weaknesses.append('May contain personal information')

        return weaknesses

    def _evaluate_length(self, password: str) -> Dict[str, Any]:
        """Evaluate password length"""
        length = len(password)
        
        if length >= 16:
            score, feedback = 100, 'Excellent length'
        elif length >= 12:
            score, feedback = 80, 'Good length'
        elif length >= 8:
            score, feedback = 60, 'Adequate length'
        elif length >= 6:
            score, feedback = 30, 'Short length'
        else:
            score, feedback = 0, 'Very short'

        return {'score': score, 'feedback': feedback, 'length': length}

    def _evaluate_complexity(self, password: str) -> Dict[str, Any]:
        """Evaluate password complexity"""
        composition = self._analyze_composition(password)
        score = 0

        if composition['has_lowercase']:
            score += 20
        if composition['has_uppercase']:
            score += 20
        if composition['has_digits']:
            score += 20
        if composition['has_symbols']:
            score += 30

        # Bonus for good distribution
        total_chars = len(password)
        if total_chars > 0:
            distribution = [
                composition['lowercase_count'] / total_chars,
                composition['uppercase_count'] / total_chars,
                composition['digit_count'] / total_chars,
                composition['symbol_count'] / total_chars
            ]
            
            variance = self._calculate_variance(distribution)
            if variance < 0.1:  # Bonus for balanced character types
                score += 10

        if score >= 80:
            feedback = 'High complexity'
        elif score >= 60:
            feedback = 'Medium complexity'
        else:
            feedback = 'Low complexity'

        return {'score': score, 'feedback': feedback}

    def _evaluate_uniqueness(self, password: str) -> Dict[str, Any]:
        """Evaluate password uniqueness"""
        score = 100
        feedback = []

        if password.lower() in self.common_passwords:
            score -= 50
            feedback.append('Common password detected')

        for pattern in self.common_patterns:
            if pattern.search(password):
                score -= 30
                feedback.append('Predictable pattern detected')
                break

        return {
            'score': max(0, score),
            'feedback': ', '.join(feedback) if feedback else 'Appears unique'
        }

    def _calculate_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate overall password score"""
        weights = {
            'length': 0.3,
            'complexity': 0.3,
            'uniqueness': 0.2,
            'entropy': 0.2
        }

        entropy_score = min(100, (analysis['entropy'] / 60) * 100)  # 60 bits = 100 score

        total_score = (
            analysis['strength']['length']['score'] * weights['length'] +
            analysis['strength']['complexity']['score'] * weights['complexity'] +
            analysis['strength']['uniqueness']['score'] * weights['uniqueness'] +
            entropy_score * weights['entropy']
        )

        return round(total_score)

    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        if score >= 80:
            return 'Low'
        elif score >= 60:
            return 'Medium'
        elif score >= 40:
            return 'High'
        else:
            return 'Critical'

    def _generate_suggestions(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable suggestions"""
        suggestions = []

        if analysis['length'] < 12:
            suggestions.append('Increase length to at least 12 characters')

        if not analysis['composition']['has_uppercase']:
            suggestions.append('Add uppercase letters')

        if not analysis['composition']['has_symbols']:
            suggestions.append('Include special characters (!@#$%^&*)')

        if not analysis['composition']['has_digits']:
            suggestions.append('Add numbers')

        if analysis['entropy'] < 50:
            suggestions.append('Increase randomness - avoid predictable patterns')

        if analysis['weaknesses']:
            suggestions.append('Avoid common passwords and patterns')

        # Always suggest best practices
        suggestions.extend([
            'Use a unique password for each account',
            'Enable two-factor authentication where possible'
        ])

        return suggestions

    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns"""
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '12345', '09876', 'qwertyuiop',
            'asdfghjkl', 'zxcvbnm', '1234567890', '0987654321'
        ]

        return any(pattern in password.lower() for pattern in keyboard_patterns)

    def _has_personal_info_pattern(self, password: str) -> bool:
        """Check for personal information patterns"""
        patterns = [
            re.compile(r'(19|20)\d{2}'),  # Years
            re.compile(r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)', re.IGNORECASE),  # Months
            re.compile(r'(admin|user|test|demo)', re.IGNORECASE),  # Common usernames
            re.compile(r'^(name|user|admin)\d+$', re.IGNORECASE)  # Simple username patterns
        ]

        return any(pattern.search(password) for pattern in patterns)

    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance for array of numbers"""
        if not values:
            return 0.0
            
        mean = sum(values) / len(values)
        variance = sum((val - mean) ** 2 for val in values) / len(values)
        return variance

    def generate_passphrase_suggestions(self, count: int = 3) -> List[str]:
        """Generate passphrase suggestions"""
        import random
        
        words = [
            'Blue', 'Tiger', 'Ocean', 'Mountain', 'River', 'Forest',
            'Storm', 'Lightning', 'Thunder', 'Rainbow', 'Crystal', 'Phoenix',
            'Dragon', 'Eagle', 'Wolf', 'Bear', 'Lion', 'Falcon'
        ]

        suggestions = []
        for _ in range(count):
            word1 = random.choice(words)
            word2 = random.choice(words)
            number = random.randint(10, 99)
            symbol = random.choice(['!', '@', '#', '$', '%'])
            
            suggestions.append(f"{word1}_{word2}{symbol}{number}")

        return suggestions