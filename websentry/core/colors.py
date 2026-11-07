"""
WebSentry Color and Terminal Formatting Module
Black/Red cybersecurity aesthetic with ANSI codes and fallback for non-TTY.
Developer: Isha Sonaria
"""

import sys
import os

# Check if colors should be disabled
_NO_COLOR = bool(os.environ.get("NO_COLOR"))
_COLOR_ENABLED = sys.stdout.isatty() and not _NO_COLOR

class Colors:
    # Reset
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Red & Crimson (Brand primary)
    RED = "\033[31m"
    BRIGHT_RED = "\033[91m"
    CRIMSON = "\033[38;5;196m"
    DARK_RED = "\033[38;5;88m"
    BG_RED = "\033[41m"
    BG_CRIMSON = "\033[48;5;196m"

    # Secondary accents
    GREEN = "\033[32m"
    BRIGHT_GREEN = "\033[92m"
    YELLOW = "\033[33m"
    BRIGHT_YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    BLUE = "\033[34m"
    BRIGHT_BLUE = "\033[94m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    BRIGHT_CYAN = "\033[96m"

    # Neutrals
    WHITE = "\033[37m"
    BRIGHT_WHITE = "\033[97m"
    GRAY = "\033[90m"
    DARK_GRAY = "\033[38;5;236m"
    LIGHT_GRAY = "\033[38;5;245m"
    BG_DARK = "\033[48;5;233m"

def set_color_enabled(enabled: bool) -> None:
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled

def is_color_enabled() -> bool:
    return _COLOR_ENABLED

def colorize(text: str, color_code: str) -> str:
    if not _COLOR_ENABLED:
        return text
    return f"{color_code}{text}{Colors.RESET}"

def red(text: str) -> str:
    return colorize(text, Colors.RED)

def bright_red(text: str) -> str:
    return colorize(text, Colors.BRIGHT_RED)

def crimson(text: str) -> str:
    return colorize(text, Colors.CRIMSON)

def dark_red(text: str) -> str:
    return colorize(text, Colors.DARK_RED)

def bold(text: str) -> str:
    return colorize(text, Colors.BOLD)

def dim(text: str) -> str:
    return colorize(text, Colors.DIM)

def yellow(text: str) -> str:
    return colorize(text, Colors.BRIGHT_YELLOW)

def orange(text: str) -> str:
    return colorize(text, Colors.ORANGE)

def green(text: str) -> str:
    return colorize(text, Colors.BRIGHT_GREEN)

def cyan(text: str) -> str:
    return colorize(text, Colors.BRIGHT_CYAN)

def white(text: str) -> str:
    return colorize(text, Colors.BRIGHT_WHITE)

def gray(text: str) -> str:
    return colorize(text, Colors.GRAY)

# Prefixes
def sym_plus() -> str:
    return colorize("[+]", Colors.BRIGHT_GREEN)

def sym_minus() -> str:
    return colorize("[-]", Colors.GRAY)

def sym_star() -> str:
    return colorize("[*]", Colors.BRIGHT_RED)

def sym_warn() -> str:
    return colorize("[!]", Colors.BRIGHT_YELLOW)

def sym_err() -> str:
    return colorize("[X]", Colors.CRIMSON + Colors.BOLD)

def sym_vuln() -> str:
    return colorize("[!]", Colors.CRIMSON + Colors.BOLD)

def format_severity(severity_str: str) -> str:
    s = severity_str.upper()
    if not _COLOR_ENABLED:
        return f"[{s}]"
    if s == "CRITICAL":
        return f"{Colors.BG_CRIMSON}{Colors.BRIGHT_WHITE}{Colors.BOLD} CRITICAL {Colors.RESET}"
    elif s == "HIGH":
        return f"{Colors.BRIGHT_RED}{Colors.BOLD}[HIGH]{Colors.RESET}"
    elif s == "MEDIUM":
        return f"{Colors.ORANGE}{Colors.BOLD}[MEDIUM]{Colors.RESET}"
    elif s == "LOW":
        return f"{Colors.BRIGHT_YELLOW}[LOW]{Colors.RESET}"
    else:
        return f"{Colors.BRIGHT_CYAN}[INFO]{Colors.RESET}"
