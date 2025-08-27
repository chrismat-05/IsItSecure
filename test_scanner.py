#!/usr/bin/env python3
"""
Test suite for IsItSecure? Password Scanner
Simple test cases to verify functionality
"""

import sys
import asyncio
from isitsecure import PasswordScanner


def run_tests():
    """Run test suite"""
    try:
        # Try to import colorama for colored output
        from colorama import Fore, Style
        colors = {
            'cyan': Fore.CYAN, 'green': Fore.GREEN, 'red': Fore.RED, 
            'yellow': Fore.YELLOW, 'bold': Style.BRIGHT, 'reset': Style.RESET_ALL
        }
    except ImportError:
        colors = {key: '' for key in ['cyan', 'green', 'red', 'yellow', 'bold', 'reset']}

    print(f"{colors['bold']}{colors['cyan']}🧪 Running IsItSecure? Test Suite\n{colors['reset']}")
    
    scanner = PasswordScanner()
    passed = 0
    failed = 0

    # Test 1: Strong password analysis
    print('Test 1: Strong password analysis')
    try:
        result = scanner.scan_password('MyStr0ng!P@ssw0rd2024', { 
            'check_breaches': False,
            'format': 'json'
        })
        
        if result['analysis']['score'] >= 70:
            print(f"{colors['green']}✅ PASSED - Strong password correctly identified{colors['reset']}")
            passed += 1
        else:
            print(f"{colors['red']}❌ FAILED - Strong password not recognized{colors['reset']}")
            failed += 1
    except Exception as error:
        print(f"{colors['red']}❌ FAILED - Error: {str(error)}{colors['reset']}")
        failed += 1

    # Test 2: Weak password detection
    print('\nTest 2: Weak password detection')
    try:
        result = scanner.scan_password('123456', { 
            'check_breaches': False,
            'format': 'json'
        })
        
        if result['analysis']['score'] <= 30 and len(result['analysis']['weaknesses']) > 0:
            print(f"{colors['green']}✅ PASSED - Weak password correctly identified{colors['reset']}")
            passed += 1
        else:
            print(f"{colors['red']}❌ FAILED - Weak password not detected{colors['reset']}")
            failed += 1
    except Exception as error:
        print(f"{colors['red']}❌ FAILED - Error: {str(error)}{colors['reset']}")
        failed += 1

    # Test 3: Entropy calculation
    print('\nTest 3: Entropy calculation')
    try:
        result = scanner.scan_password('aB3$', { 
            'check_breaches': False,
            'format': 'json'
        })
        
        if result['analysis']['entropy'] > 0:
            print(f"{colors['green']}✅ PASSED - Entropy calculated correctly{colors['reset']}")
            passed += 1
        else:
            print(f"{colors['red']}❌ FAILED - Entropy calculation failed{colors['reset']}")
            failed += 1
    except Exception as error:
        print(f"{colors['red']}❌ FAILED - Error: {str(error)}{colors['reset']}")
        failed += 1

    # Test 4: Breach check (with known breached password)
    print('\nTest 4: Breach database check')
    try:
        print('Checking known breached password...')
        result = scanner.scan_password('password', { 
            'check_breaches': True,
            'format': 'json'
        })
        
        if result['breach_data']['is_breached'] == True and result['breach_data']['breach_count'] > 0:
            print(f"{colors['green']}✅ PASSED - Breach detection working{colors['reset']}")
            passed += 1
        elif result['breach_data'].get('error'):
            print(f"{colors['yellow']}⚠️ SKIPPED - Breach API not available{colors['reset']}")
            # Don't count as failed since it's external dependency
        else:
            print(f"{colors['red']}❌ FAILED - Breach detection not working{colors['reset']}")
            failed += 1
    except Exception as error:
        print(f"{colors['yellow']}⚠️ SKIPPED - Breach check error: {str(error)}{colors['reset']}")

    # Test 5: Batch processing
    print('\nTest 5: Batch processing')
    try:
        test_passwords = ['weak123', 'StrongP@ssw0rd!2024', '12345']
        results = scanner.scan_batch(test_passwords, { 
            'check_breaches': False 
        })
        
        if len(results) == 3:
            print(f"{colors['green']}✅ PASSED - Batch processing working{colors['reset']}")
            passed += 1
        else:
            print(f"{colors['red']}❌ FAILED - Batch processing failed{colors['reset']}")
            failed += 1
    except Exception as error:
        print(f"{colors['red']}❌ FAILED - Error: {str(error)}{colors['reset']}")
        failed += 1

    # Test Summary
    print(f"{colors['bold']}\n📊 TEST RESULTS{colors['reset']}")
    print(f"Passed: {colors['green']}{passed}{colors['reset']}")
    print(f"Failed: {colors['red']}{failed}{colors['reset']}")
    print(f"Total: {passed + failed}")

    if failed == 0:
        print(f"{colors['green']}{colors['bold']}\n🎉 All tests passed! IsItSecure? is working correctly.{colors['reset']}")
    else:
        print(f"{colors['yellow']}{colors['bold']}\n⚠️ Some tests failed. Please review the implementation.{colors['reset']}")


if __name__ == '__main__':
    try:
        run_tests()
    except Exception as error:
        print(f"Fatal error: {str(error)}")
        sys.exit(1)