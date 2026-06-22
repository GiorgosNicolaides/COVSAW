import random
import sys
import time
import os

from colorama import Fore, Style, init


def get_ascii_art() -> str:
    """
    Return a randomly chosen, colored ASCII-art banner.
    """
    banner1 = r"""

   ______ __ __    _ _____ ___ _       _       
  / ____/ __ \ |  / / ___//   | |     / /
 / /   / / / / | / /\__ \/ /| | | /| / / 
/ /___/ /_/ /| |/ /___/ / ___ | |/ |/ /  
\____/\____/ |___//____/_/  |_|__/|__/   
                                        


Classification Of Cryptographic Vulnerabilities and Security Assessment of Web applications 

    """

    banner2 = r"""
  ___  __   _  _  ____   __   _  _
 / __)/  \ / )( \/ ___) /  \ / )( \
( (__(  O )\ \/ /\___ \/ /\ \\ /\ /
 \___)\__/  \__/ (____/\_/\_/(_/\_)



 Classification Of Cryptographic Vulnerabilities and Security Assessment of Web applications 

"""

    banner3 = r"""
 ▗▄▄▖ ▗▄▖ ▗▖  ▗▖ ▗▄▄▖ ▗▄▖ ▗▖ ▗▖
▐▌   ▐▌ ▐▌▐▌  ▐▌▐▌   ▐▌ ▐▌▐▌ ▐▌
▐▌   ▐▌ ▐▌▐▌  ▐▌ ▝▀▚▖▐▛▀▜▌▐▌ ▐▌
▝▚▄▄▖▝▚▄▞▘ ▝▚▞▘ ▗▄▄▞▘▐▌ ▐▌▐▙█▟▌



 Classification Of Cryptographic Vulnerabilities and Security Assessment of Web applications 

"""

    arts = [banner1, banner2, banner3]
    art = random.choice(arts)

    # Apply coloring using colorama
    color_choices = [Fore.RED, Fore.GREEN, Fore.BLUE]
    art_with_color = ""
    lines = art.split('\n')
    for line in lines:
        color = random.choice(color_choices)
        art_with_color += color + line + "\n"
    art_with_color += Style.RESET_ALL

    return art_with_color


def print_banner(duration: float = 2.5) -> None:
    """
    Prints the ASCII-art banner (for `duration` seconds) and then clears it.
    Default duration is 2.5 seconds.
    """
    # Only display the decorative banner in an interactive terminal. When stdout
    # is redirected or piped (e.g. `-f json > out.json`), skip it entirely so the
    # report on stdout is never polluted with banner art or clear-screen escapes.
    if not (sys.stdout.isatty() and sys.stderr.isatty()):
        return

    init(autoreset=True)
    ascii_art = get_ascii_art()
    # Write the banner to stderr to keep stdout reserved for machine-readable output.
    print(ascii_art, file=sys.stderr)
    time.sleep(duration)

    # Clear the banner from the terminal
    if os.name == "nt":
        _ = os.system("cls")
    else:
        _ = os.system("clear")
