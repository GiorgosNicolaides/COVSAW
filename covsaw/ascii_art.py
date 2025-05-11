import random
from colorama import Fore, Back, Style, init
import time


def get_ascii_art():
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

    # Apply RGB coloring to the ASCII Art using ANSI escape codes
    # Cycle through Red, Green, Blue colors
    color_choices = [Fore.RED, Fore.GREEN, Fore.BLUE]
    art_with_color = ""
    lines = art.split('\n')
    for line in lines:
        color = random.choice(color_choices)
        art_with_color += color + line + '\n'

    return art_with_color


# Function to rotate ASCII art
def print_banner():
        # Get a randomly rotated ASCII art
        ascii_art = get_ascii_art()
        print(ascii_art)
        time.sleep(1)  

# Run the function
if __name__ == "__main__":
    print_banner()