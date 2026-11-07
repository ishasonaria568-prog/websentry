"""
WebSentry Banner and Identity Module
Displays the official ASCII art banner, developer credits, version info, and legal notice.
Developer: Isha Sonaria
"""

from websentry.core.colors import (
    crimson, bright_red, dark_red, bold, dim, yellow, cyan, white, gray, Colors, is_color_enabled
)

VERSION = "1.2.0"
AUTHOR = "Isha Sonaria"
GITHUB = "https://github.com/ishasonaria568-prog"
TAGLINE = "Web Server Security Assessment Tool"

ASCII_ART = r"""
 __      __      ___.    _________               __                       
/  \    /  \ ____\_ |__ /   _____/____   _______/  |________ ___.__.      
\   \/\/   // __ \| __ \\_____  \/ __ \ /    /\   __\_  __ <   |  |      
 \        /\  ___/| \_\ \        \  ___/|   |  \|  |  |  | \/\___  |      
  \__/\  /  \___  >___  /_______  /\___  >___|  /|__|  |__|   / ____|      
       \/       \/    \/        \/     \/     \/             \/           
"""

ASCII_MINI = r"""
 _ _ _     _   _____         _              
| | | |___| |_|   __|___ ___| |_ ___ _ _    
| | | | -_| . |__   | -_|   |  _|  _| | |   
|_____|___|___|_____|___|_|_|_| |_| |_  |   
                                    |___|   
"""

def get_banner(mini: bool = False) -> str:
    """Returns the formatted ASCII banner with red/black cybersecurity styling."""
    art = ASCII_MINI if mini else ASCII_ART
    
    lines = []
    # Banner art with crimson gradient
    if is_color_enabled():
        colored_art = f"{Colors.CRIMSON}{Colors.BOLD}{art.strip()}{Colors.RESET}"
    else:
        colored_art = art.strip()
    
    lines.append(colored_art)
    lines.append("")
    
    # Prominent Branding
    dev_badge = f"{Colors.BG_CRIMSON}{Colors.BRIGHT_WHITE}{Colors.BOLD} BUILT BY ISHA SONARIA {Colors.RESET}" if is_color_enabled() else "[ BUILT BY ISHA SONARIA ]"
    lines.append(f"  {dev_badge}   {bold(white(TAGLINE))}")
    
    meta_line = (
        f"  {gray('Version:')} {bright_red(f'v{VERSION}')}  |  "
        f"{gray('GitHub:')} {cyan(GITHUB)}  |  "
        f"{gray('Engine:')} {yellow('Nikto-Inspired v1.2')}"
    )
    lines.append(meta_line)
    lines.append(f"  {gray('──────────────────────────────────────────────────────────────────────────')}")
    
    return "\n".join(lines)

def print_banner(mini: bool = False) -> None:
    """Prints the startup banner to stdout."""
    print(get_banner(mini))

def print_legal_notice() -> None:
    """Prints safety and legal authorization disclaimer."""
    notice = (
        f"  {yellow('[!] LEGAL DISCLAIMER:')} {gray('This tool is intended for authorized security')}\n"
        f"  {gray('assessments, penetration tests, and defensive audits only. Scanning targets')}\n"
        f"  {gray('without explicit prior written consent is strictly illegal and prohibited.')}"
    )
    print(notice)
    print(f"  {gray('──────────────────────────────────────────────────────────────────────────')}")
