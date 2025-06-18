import re
import sys
from argparse import ArgumentParser
from resources import console

class NetSeekerArgumentParser(ArgumentParser):
    def get_command(self):
        if len(sys.argv) > 1:
            potential_command = sys.argv[1]

            if potential_command in ['portscan', 'netscan', 'traceroute', 'sdenum']:
                return potential_command
        
        return None


    def print_help(self, file = None):
        if file is None:
            file = sys.stdout

        return super().print_help(file)

    
    def print_usage(self, command = None, file = None):
        if file is None:
            file = sys.stdout

        match command:
            case ('portscan'):  
                console.print(f"Usage: netseeker portscan [TARGET] [OPTIONS]\nExample: netseeker portscan 192.168.1.1 --ports 21,53,587")
            case ('netscan'):
                console.print(f"Usage: netseeker netscan [TARGET] [OPTIONS]\nExample: netseeker netscan 192.168.1.0/24 --retries 3 --verbose")
            case ('traceroute'):
                console.print(f"Usage: netseeker traceroute [TARGET] [OPTIONS]\nExample: netseeker traceroute google.com --generate-map")
            case ('sdenum'):
                console.print(f"Usage: netseeker sdenum [TARGET] [OPTIONS]\nExample: netseeker sdenum example.com --output --wordlist /path/to/wordlist.txt")
            case _:
                console.print(f"Usage: netseeker COMMAND [ARGS] [OPTIONS]")

        console.print(f"\nTry 'netseeker --help/-h' for more information about the commands.")

    
    def error(self, message):
        # return super().error(message)
        command = self.get_command()

        # Invalid command.
        if match := re.search(r"argument command: invalid choice: '([^']+)'", message):
            invalid_item = match.group(1)
            console.print(f"[bold red]ERROR:[/bold red] Invalid command: '{invalid_item}'")
            self.suggest_commands(invalid_item)
        
        # Invalid choice (https://docs.python.org/3/library/argparse.html#choices).
        elif match := re.search(r"argument move: invalid choice: '([^']+)'", message):
            console.print(f"[bold red]ERROR: [/bold red] ")
            self.print_usage(command)
        
        # Invalid arguments.
        elif match := re.search(r"unrecognized arguments: (.+)", message):
            invalid_item = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Invalid option: '{invalid_item}'")
            self.suggest_options(invalid_item)
        
        # Missing required arguments.
        elif match := re.search(r"the following arguments are required: (.+)", message):
            missing_args = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Missing argument: '{missing_args}'")
            self.print_usage(command)

        else:
            return super().error(message)

        raise SystemExit(2)


    def suggest_commands(self, invalid_command):
        pass


    def suggest_options(self, invalid_option):
        pass