"""
WebSentry Command Line Interface (CLI)
Developer: Isha Sonaria
GitHub: https://github.com/ishasonaria568-prog
"""

import sys
import os
import argparse
from typing import List, Optional
from websentry import __version__, __author__, __github__, __tagline__
from websentry.banner import print_banner, print_legal_notice, get_banner
from websentry.core.colors import (
    set_color_enabled, crimson, bright_red, yellow, cyan, green, white, gray, bold,
    sym_plus, sym_star, sym_warn, sym_err
)
from websentry.core.config import ScanConfig
from websentry.core.engine import ScanEngine
from websentry.core.safety import TargetSafetyRefusalError, InvalidTargetURLError
from websentry.reports.generator import ReportGenerator
from websentry.modules.nikto_signatures import NiktoSignatureScanner

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websentry",
        description="WebSentry — Professional CLI-Based Web Server Security Scanner (Built by Isha Sonaria)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  websentry scan -u http://127.0.0.1:8080
  websentry scan -u https://example.com --allow-public
  websentry scan -u https://example.com --quick --allow-public
  websentry scan -u https://example.com --full --allow-public
  websentry scan -u https://example.com --headers --allow-public
  websentry scan -u https://example.com --ssl --allow-public
  websentry scan -u https://example.com --methods --allow-public
  websentry scan -u https://example.com --format html --allow-public
  websentry scan -u https://example.com --output reports/audit.json --allow-public
  websentry update
  websentry version

Developer Credit:
  Built by ISHA SONARIA (https://github.com/ishasonaria568-prog)
"""
    )
    parser.add_argument("-V", "--version", action="store_true", help="Show WebSentry version and developer credit")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")

    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run a security assessment against a target web server")
    scan_parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://127.0.0.1:8080 or https://example.com)")
    
    # Modes
    mode_group = scan_parser.add_mutually_exclusive_group()
    mode_group.add_argument("--quick", action="store_true", help="Fast scan of high-risk vectors and critical signatures")
    mode_group.add_argument("--full", action="store_true", help="Comprehensive deep scan of all modules and full signature DB")
    
    # Specific modules
    scan_parser.add_argument("--headers", action="store_true", help="Scan HTTP headers and information disclosure only")
    scan_parser.add_argument("--ssl", action="store_true", help="Scan SSL/TLS certificates and protocols only")
    scan_parser.add_argument("--methods", action="store_true", help="Scan enabled HTTP verbs and test dangerous methods only")
    scan_parser.add_argument("--files", action="store_true", help="Scan sensitive files and backup directories only")
    scan_parser.add_argument("--nikto", action="store_true", help="Run Nikto-inspired signature checks only")

    # Reporting
    scan_parser.add_argument("-o", "--output", help="Save report to specified file path (.json, .html, .txt)")
    scan_parser.add_argument("-f", "--format", choices=["json", "html", "txt", "all"], default="json", help="Report format (default: json)")

    # Performance & Concurrency
    scan_parser.add_argument("-t", "--threads", type=int, default=6, help="Concurrent worker threads (default: 6)")
    scan_parser.add_argument("--timeout", type=float, default=8.0, help="HTTP request timeout in seconds (default: 8.0)")
    scan_parser.add_argument("--delay", type=float, default=0.05, help="Rate-limit delay between requests in seconds (default: 0.05)")
    scan_parser.add_argument("--retries", type=int, default=2, help="Connection retries on transient errors (default: 2)")

    # Safety & Customization
    scan_parser.add_argument("--allow-public", action="store_true", help="Explicitly authorize scanning of public internet targets")
    scan_parser.add_argument("--signatures", help="Path to custom signature database JSON file")
    scan_parser.add_argument("-k", "--insecure", action="store_true", help="Allow insecure SSL connections (disable TLS verify for local tests)")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug and progress logs")

    # Command: update
    subparsers.add_parser("update", help="Check and update signature database")

    # Command: version
    subparsers.add_parser("version", help="Display tool version and author details")

    # Command: help
    subparsers.add_parser("help", help="Display detailed help and usage examples")

    return parser

def cmd_version() -> int:
    print_banner()
    print(f"  {bold('WebSentry Core Version:')} {bright_red(f'v{__version__}')}")
    print(f"  {bold('Developer:')}           {crimson(__author__)}")
    print(f"  {bold('GitHub Profile:')}      {cyan(__github__)}")
    print(f"  {bold('License:')}             MIT License")
    print(f"  {bold('Platform Support:')}    Kali Linux, Debian, Ubuntu, macOS, Windows\n")
    return 0

def cmd_update(signatures_path: Optional[str] = None) -> int:
    print_banner(mini=True)
    print(f"{sym_star()} {bold('Checking WebSentry Signature Database...')}")
    scanner = NiktoSignatureScanner(signatures_path=signatures_path)
    count = scanner.get_signatures_count()
    print(f"  {sym_plus()} Signature engine:       {bold(green('Active'))}")
    print(f"  {sym_plus()} Installed signatures:   {bold(yellow(str(count)))} rules")
    print(f"  {sym_plus()} Status:                 {green('All signatures are up to date.')}")
    print(f"  {sym_plus()} Local database path:    {gray(scanner.signatures_path or 'websentry/signatures/default_signatures.json')}\n")
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    print_banner()
    print_legal_notice()

    # Determine mode
    mode = "standard"
    if args.quick:
        mode = "quick"
    elif args.full:
        mode = "full"

    # Determine modules
    modules = []
    if args.headers:
        modules.append("headers")
    if args.ssl:
        modules.append("ssl")
    if args.methods:
        modules.append("methods")
    if args.files:
        modules.append("sensitive_files")
    if args.nikto:
        modules.append("nikto")

    # Default to all modules if none specifically chosen
    if not modules:
        modules = ["ssl", "headers", "methods", "server_info", "misconfigs", "sensitive_files", "nikto"]

    config = ScanConfig(
        url=args.url,
        mode=mode,
        modules=modules,
        timeout=args.timeout,
        threads=args.threads,
        delay=args.delay,
        retries=args.retries,
        allow_public=args.allow_public,
        output_file=args.output,
        output_format=args.format,
        signatures_path=args.signatures,
        verify_ssl=not args.insecure,
        verbose=args.verbose,
        no_color=args.no_color
    )

    try:
        engine = ScanEngine(config)
        findings = engine.run()
        engine.print_summary()

        # Generate and save reports
        reporter = ReportGenerator(
            target_url=config.url,
            findings=findings,
            duration_seconds=engine.duration,
            total_requests=engine.total_requests,
            version=__version__,
            author=__author__,
            github=__github__
        )

        saved = reporter.save_reports(output_path=config.output_file, fmt=config.output_format)
        if saved:
            print(f"{sym_plus()} {bold(green('Report(s) successfully generated:'))}")
            for p in saved:
                print(f"    {cyan(p)}")
            print()

        return 0

    except TargetSafetyRefusalError:
        return 2
    except InvalidTargetURLError as e:
        print(f"\n{sym_err()} {bright_red(f'Configuration Error: {e}')}\n")
        return 1
    except Exception as e:
        print(f"\n{sym_err()} {bright_red(f'Unexpected runtime error: {e}')}\n")
        if config.verbose:
            import traceback
            traceback.print_exc()
        return 1

def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        set_color_enabled(False)

    if args.version:
        return cmd_version()

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    if args.command == "version":
        return cmd_version()
    elif args.command == "update":
        return cmd_update()
    elif args.command == "help":
        print_banner()
        parser.print_help()
        return 0
    elif args.command == "scan":
        return cmd_scan(args)
    else:
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())
