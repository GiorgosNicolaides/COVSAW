import random
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
                                        


Classification of Cryptograhic Vulnerabilies and Security Assesment of Web Appilcations 

    """

    banner2 = r"""
  ___  __   _  _  ____   __   _  _
 / __)/  \ / )( \/ ___) /  \ / )( \
( (__(  O )\ \/ /\___ \/ /\ \\ /\ /
 \___)\__/  \__/ (____/\_/\_/(_/\_)



 Classification of Cryptograhic Vulnerabilies and Security Assesment of Web Appilcations 

"""

    banner3 = r"""
 ▗▄▄▖ ▗▄▖ ▗▖  ▗▖ ▗▄▄▖ ▗▄▖ ▗▖ ▗▖
▐▌   ▐▌ ▐▌▐▌  ▐▌▐▌   ▐▌ ▐▌▐▌ ▐▌
▐▌   ▐▌ ▐▌▐▌  ▐▌ ▝▀▚▖▐▛▀▜▌▐▌ ▐▌
▝▚▄▄▖▝▚▄▞▘ ▝▚▞▘ ▗▄▄▞▘▐▌ ▐▌▐▙█▟▌



 Classification of Cryptograhic Vulnerabilies and Security Assesment of Web Appilcations 

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
    init(autoreset=True)
    ascii_art = get_ascii_art()
    print(ascii_art)
    time.sleep(duration)

    # Clear the banner from the terminal
    if os.name == "nt":
        _ = os.system("cls")
    else:
        _ = os.system("clear")
