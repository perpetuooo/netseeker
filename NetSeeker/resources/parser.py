import re
import sys
import argparse
from resources import console

class NetSeekerArgumentParser(argparse.ArgumentParser):
    @property
    def _commands(self):
        # Cache commands to avoid re-parsing.
        if not hasattr(self, '_cached_commands_dict'):
            self._cached_commands_dict = {}

            for action in self._actions:
                if isinstance(action, argparse._SubParsersAction):
                    self._cached_commands_dict = dict(action.choices)
                    break

        return self._cached_commands_dict


    def get_current_command(self):
        commands = set(self._commands.keys())
        
        for arg in sys.argv[1:]:
            if arg in commands:
                return arg

        return None


    def get_command_options(self, command):
        options = []

        if command not in self._commands:
            return options
        
        # Cache options to avoid re-parsing
        if not hasattr(self, '_cached_command_options'):
            self._cached_command_options = {}
        
        if command not in self._cached_command_options:
            subparser = self._commands[command]
            
            for action in subparser._actions:
                if action.option_strings:
                    options.extend(action.option_strings)   # Interleaving: [0] = '-h' / [1] = '--help' / [2] = '--ports' / [3] = '-p'...
            
            self._cached_command_options[command] = options
        
        return self._cached_command_options[command]


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

        console.print(f"Try 'netseeker --help' for more information.")

    
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