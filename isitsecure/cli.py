#!/usr/bin/env python3
"""
Command Line Interface for IsItSecure? Password Scanner
"""

import argparse
import sys
import getpass
from typing import Optional

from .password_scanner import PasswordScanner


def prompt_password(prompt: str = "Enter password to check: ") -> str:
    """Prompt for password input (hidden)"""
    import sys
    password = ''
    print(prompt, end='', flush=True)
    try:
        import msvcrt
        while True:
            ch = msvcrt.getch()
            if ch in (b'\r', b'\n'):
                print()
                break
            elif ch == b'\x03':
                raise KeyboardInterrupt
            elif ch == b'\x08':
                if len(password) > 0:
                    password = password[:-1]
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch in (b'\x00', b'\xe0'):
                msvcrt.getch()
            else:
                try:
                    char = ch.decode('utf-8')
                except Exception:
                    continue
                password += char
                sys.stdout.write('●')
                sys.stdout.flush()
        return password
    except KeyboardInterrupt:
        print('\nCancelled.')
        sys.exit(1)
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)


def cmd_check(args) -> None:
    """Handle check command"""
    scanner = PasswordScanner()
    
    try:
        password = args.password
        
        if not password:
            password = prompt_password('Enter password to check: ')

        result = scanner.scan_password(password, {
            'check_breaches': args.breach,
            'format': 'json' if args.json else 'console'
        })

        if args.json:
            import json
            print(json.dumps(result, indent=2))

        if args.output:
            scanner.report_generator.export_to_json(result, args.output)

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)


def cmd_batch(args) -> None:
    """Handle batch command"""
    scanner = PasswordScanner()
    
    try:
        if not args.file:
            print("❌ File path is required for batch mode")
            sys.exit(1)

        passwords = scanner.load_passwords_from_file(args.file)
        print(f"📁 Loaded {len(passwords)} passwords from {args.file}")

        results = scanner.scan_batch(passwords, {
            'check_breaches': args.breach
        })

        if args.output:
            scanner.report_generator.export_to_json(results, args.output)

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)


def cmd_generate(args) -> None:
    """Handle generate command"""
    scanner = PasswordScanner()
    count = int(args.count)
    
    try:
        # Try to import colorama for colored output
        from colorama import Fore, Style
        colors = {'cyan': Fore.CYAN, 'green': Fore.GREEN, 'reset': Style.RESET_ALL, 'bold': Style.BRIGHT}
    except ImportError:
        colors = {'cyan': '', 'green': '', 'reset': '', 'bold': ''}
    
    print(f"\n{colors['bold']}{colors['cyan']}🔐 SECURE PASSWORD SUGGESTIONS{colors['reset']}")
    print('=' * 50)
    
    suggestions = scanner.generate_suggestions(count)
    for i, suggestion in enumerate(suggestions, 1):
        print(f"{i}. {colors['green']}{suggestion}{colors['reset']}")
    
    print(f"\n💡 These passphrases combine memorable words with symbols and numbers")
    print(f"   for both security and usability.")


def cmd_demo(args) -> None:
    """Handle demo command"""
    scanner = PasswordScanner()
    demo_passwords = [
        'password123',
        'MyStr0ng!P@ssw0rd',
        '123456',
        'Blue_Tiger!82',
        'qwerty'
    ]

    try:
        # Try to import colorama for colored output
        from colorama import Fore, Style
        colors = {'cyan': Fore.CYAN, 'bold': Style.BRIGHT, 'reset': Style.RESET_ALL}
    except ImportError:
        colors = {'cyan': '', 'bold': '', 'reset': ''}

    print(f"{colors['bold']}{colors['cyan']}\n🎯 DEMONSTRATION MODE{colors['reset']}")
    print('Testing with sample passwords to show capabilities...\n')

    try:
        scanner.scan_batch(demo_passwords, {'check_breaches': True})
    except Exception as e:
        print(f"❌ Demo error: {str(e)}")
        sys.exit(1)


def main() -> None:
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='isitsecure',
        description=(
                'IsItSecure? is a secure Password Health Scanner which also analyzes password strength and breach exposure\n\n'
        )
    )
    parser.add_argument('--version', action='version', version='IsItSecure? 1.0.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Check command
    check_parser = subparsers.add_parser(
        'check',
        help='Check a single password. Usage: check -p <pwd> [--no-breach] [--json] [--output <file>]'
    )
    check_parser.add_argument('-p', '--password', help='Password to check')
    check_parser.add_argument('--no-breach', dest='breach', action='store_false', 
                             help='Skip breach database check')
    check_parser.add_argument('-o', '--output', help='Export results to JSON file')
    check_parser.add_argument('--json', action='store_true', help='Output in JSON format')
    check_parser.set_defaults(func=cmd_check)
    
    # Batch command
    batch_parser = subparsers.add_parser(
        'batch',
        help='Check multiple passwords from file. Usage: batch -f <file> [--no-breach] [--output <file>]'
    )
    batch_parser.add_argument('-f', '--file', help='File containing passwords (one per line)')
    batch_parser.add_argument('--no-breach', dest='breach', action='store_false',
                             help='Skip breach database checks')
    batch_parser.add_argument('-o', '--output', help='Export results to JSON file')
    batch_parser.set_defaults(func=cmd_batch)
    
    # Generate command
    generate_parser = subparsers.add_parser(
        'generate',
        help='Generate secure password suggestions. Usage: generate -c <number of passwords to be gen>'
    )
    generate_parser.add_argument('-c', '--count', default='3', 
                                help='Number of suggestions to generate')
    generate_parser.set_defaults(func=cmd_generate)
    
    # Demo command
    demo_parser = subparsers.add_parser(
        'demo',
        help='Run demonstration with sample passwords.'
    )
    demo_parser.set_defaults(func=cmd_demo)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Handle unhandled exceptions
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()