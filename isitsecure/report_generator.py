"""
Report Generator
Creates formatted reports for password analysis results
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime


class ReportGenerator:
    """
    Report generator for password analysis results
    """
    
    def __init__(self):
        # Try to import colorama for colored output
        try:
            from colorama import init, Fore, Style
            init(autoreset=True)
            self.colors = {
                'critical': Fore.RED + Style.BRIGHT,
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.GREEN,
                'safe': Fore.GREEN + Style.BRIGHT,
                'reset': Style.RESET_ALL,
                'bold': Style.BRIGHT,
                'cyan': Fore.CYAN,
                'blue': Fore.BLUE,
                'yellow': Fore.YELLOW,
                'red': Fore.RED,
                'green': Fore.GREEN
            }
            self.has_colors = True
        except ImportError:
            # Fallback to no colors if colorama is not available
            self.colors = {key: '' for key in [
                'critical', 'high', 'medium', 'low', 'safe', 'reset', 
                'bold', 'cyan', 'blue', 'yellow', 'red', 'green'
            ]}
            self.has_colors = False

    def generate_console_report(self, analysis: Dict[str, Any], breach_data: Dict[str, Any]) -> None:
        """Generate console report for single password"""
        print('\n' + '=' * 60)
        print(f"{self.colors['bold']}{self.colors['cyan']}🔒 PASSWORD SECURITY REPORT{self.colors['reset']}")
        print('=' * 60)

        # Basic Info
        print(f"{self.colors['bold']}\n📊 ANALYSIS SUMMARY{self.colors['reset']}")
        print(f"Password Length: {analysis['length']} characters")
        print(f"Security Score: {self._colorize_score(analysis['score'])}/100")
        print(f"Risk Level: {self._colorize_risk(analysis['risk_level'])}")
        print(f"Entropy: {round(analysis['entropy'])} bits")

        # Breach Information
        print(f"{self.colors['bold']}\n🔓 BREACH EXPOSURE{self.colors['reset']}")
        if breach_data.get('error'):
            print(f"{self.colors['red']}⚠️ {breach_data['error']}{self.colors['reset']}")
        elif breach_data.get('is_breached') is True:
            print(f"{self.colors['red']}❌ Found in known data breaches ({breach_data.get('breach_count', 0)} times){self.colors['reset']}")
        elif breach_data.get('is_breached') is False:
            print(f"{self.colors['green']}✅ Not found in known data breaches{self.colors['reset']}")
        elif breach_data.get('is_breached') is None and not breach_data.get('error'):
            print(f"{self.colors['yellow']}⏭️ Breach check skipped{self.colors['reset']}")
        else:
            print(f"{self.colors['yellow']}⏭️ Breach check status unknown{self.colors['reset']}")

        # Composition Details
        print(f"{self.colors['bold']}\n🧩 CHARACTER COMPOSITION{self.colors['reset']}")
        comp = analysis['composition']
        print(f"Lowercase: {'✅' if comp['has_lowercase'] else '❌'} ({comp['lowercase_count']})")
        print(f"Uppercase: {'✅' if comp['has_uppercase'] else '❌'} ({comp['uppercase_count']})")
        print(f"Digits: {'✅' if comp['has_digits'] else '❌'} ({comp['digit_count']})")
        print(f"Symbols: {'✅' if comp['has_symbols'] else '❌'} ({comp['symbol_count']})")

        # Weaknesses
        if analysis['weaknesses']:
            print(f"{self.colors['bold']}\n⚠️  IDENTIFIED WEAKNESSES{self.colors['reset']}")
            for i, weakness in enumerate(analysis['weaknesses'], 1):
                print(f"{self.colors['yellow']}{i}. {weakness}{self.colors['reset']}")

        # Suggestions
        if analysis['suggestions']:
            print(f"{self.colors['bold']}\n💡 RECOMMENDATIONS{self.colors['reset']}")
            for i, suggestion in enumerate(analysis['suggestions'], 1):
                print(f"{self.colors['blue']}{i}. {suggestion}{self.colors['reset']}")

        print('\n' + '=' * 60)

    def generate_batch_report(self, results: List[Dict[str, Any]]) -> None:
        """Generate batch report table"""
        print(f"\n{self.colors['bold']}{self.colors['cyan']}📊 BATCH PASSWORD SECURITY REPORT{self.colors['reset']}")
        print('=' * 80)

        # Try to use tabulate for better formatting
        try:
            from tabulate import tabulate
            
            table_data = []
            headers = ['#', 'Password', 'Score', 'Risk', 'Breached', 'Count', 'Status']
            
            for i, result in enumerate(results):
                analysis = result.get('analysis', {})
                breach_data = result.get('breach_data', {})
                # Determine breach status for table
                if breach_data.get('is_breached') is None and not breach_data.get('error'):
                    breach_status = 'Skipped'
                elif breach_data.get('is_breached') is True:
                    breach_status = 'YES'
                elif breach_data.get('is_breached') is False:
                    breach_status = 'NO'
                elif breach_data.get('error'):
                    breach_status = 'Error'
                else:
                    breach_status = 'Unknown'
                breach_count = breach_data.get('breach_count', 0)
                password_display = analysis.get('password', '')[:20]
                if len(analysis.get('password', '')) > 20:
                    password_display += '...'
                table_data.append([
                    str(i + 1),
                    password_display,
                    str(analysis.get('score', 0)),
                    analysis.get('risk_level', 'Unknown'),
                    breach_status,
                    f"{breach_count:,}",
                    self._get_status_emoji(analysis.get('score', 0), breach_data.get('is_breached'))
                ])

            print(tabulate(table_data, headers=headers, tablefmt='grid'))
            
        except ImportError:
            # Fallback to simple formatting
            print(f"{'#':<3} {'Password':<20} {'Score':<5} {'Risk':<8} {'Breached':<8} {'Count':<10} {'Status':<6}")
            print('-' * 70)
            
            for i, result in enumerate(results):
                analysis = result.get('analysis', {})
                breach_data = result.get('breach_data', {})
                
                breach_status = 'Unknown' if breach_data.get('is_breached') is None else \
                               'YES' if breach_data.get('is_breached') else 'NO'
                breach_count = breach_data.get('breach_count', 0)
                
                password_display = analysis.get('password', '')[:20]
                if len(analysis.get('password', '')) > 20:
                    password_display += '...'
                
                status = self._get_status_emoji(analysis.get('score', 0), breach_data.get('is_breached'))
                
                print(f"{i+1:<3} {password_display:<20} {analysis.get('score', 0):<5} "
                      f"{analysis.get('risk_level', 'Unknown'):<8} {breach_status:<8} "
                      f"{breach_count:<10,} {status:<6}")

        # Summary statistics
        total_passwords = len(results)
        breached_count = sum(1 for r in results if r.get('breach_data', {}).get('is_breached'))
        critical_count = sum(1 for r in results if r.get('analysis', {}).get('risk_level') == 'Critical')
        high_risk_count = sum(1 for r in results if r.get('analysis', {}).get('risk_level') == 'High')

        print(f"{self.colors['bold']}\n📈 SUMMARY STATISTICS{self.colors['reset']}")
        print(f"Total passwords analyzed: {total_passwords}")
        print(f"Passwords found in breaches: {self.colors['red']}{breached_count}{self.colors['reset']} "
              f"({round(breached_count/total_passwords*100) if total_passwords > 0 else 0}%)")
        print(f"Critical risk passwords: {self.colors['red']}{critical_count}{self.colors['reset']} "
              f"({round(critical_count/total_passwords*100) if total_passwords > 0 else 0}%)")
        print(f"High risk passwords: {self.colors['yellow']}{high_risk_count}{self.colors['reset']} "
              f"({round(high_risk_count/total_passwords*100) if total_passwords > 0 else 0}%)")

    def export_to_json(self, results: Any, filename: str) -> None:
        """Export results to JSON"""
        try:
            export_data = {
                'report_info': {
                    'created_by': 'IsItSecure',
                    'project_url': 'https://github.com/chrismat-05/IsItSecure'
                },
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.0',
                'results': results if isinstance(results, list) else [results]
            }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            print(f"{self.colors['green']}\n✅ Report exported to: {filename}{self.colors['reset']}")
        except Exception as e:
            print(f"{self.colors['red']}❌ Failed to export report: {str(e)}{self.colors['reset']}")

    def _colorize_score(self, score: int) -> str:
        """Colorize score based on value"""
        if score >= 80:
            return f"{self.colors['green']}{score}{self.colors['reset']}"
        elif score >= 60:
            return f"{self.colors['yellow']}{score}{self.colors['reset']}"
        elif score >= 40:
            return f"{self.colors['red']}{score}{self.colors['reset']}"
        else:
            return f"{self.colors['critical']}{score}{self.colors['reset']}"

    def _colorize_risk(self, risk_level: str) -> str:
        """Colorize risk level"""
        color_map = {
            'low': self.colors['green'],
            'medium': self.colors['yellow'],
            'high': self.colors['red'],
            'critical': self.colors['critical']
        }
        
        color = color_map.get(risk_level.lower(), '')
        return f"{color}{risk_level}{self.colors['reset']}"

    def _get_status_emoji(self, score: int, is_breached: Optional[bool]) -> str:
        """Get status emoji based on analysis"""
        if is_breached:
            return '🚨'
        elif score >= 80:
            return '✅'
        elif score >= 60:
            return '⚠️'
        else:
            return '❌'