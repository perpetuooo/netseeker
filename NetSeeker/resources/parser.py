import re
import sys
import argparse
from resources import console
from rapidfuzz import process, fuzz

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
        commands = self._commands.keys()
        
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
        console.print(command)
        if file is None:
            file = sys.stdout

        commands = self._commands.keys()
            
        if command in commands:
            console.print(f"Try 'netseeker {command} --help' for more information.")
        else:
            console.print(f"Try 'netseeker --help' for more information.")

    
    def error(self, message):
        # return super().error(message)

        # Invalid command.
        if match := re.search(r"argument command: invalid choice: '([^']+)'", message):
            invalid_item = match.group(1)
            console.print(f"[bold red]ERROR:[/bold red] Invalid command: '{invalid_item}'")
            self.suggest_commands(invalid_item)
        
        # Invalid choice (https://docs.python.org/3/library/argparse.html#choices).
        elif match := re.search(r"argument move: invalid choice: '([^']+)'", message):
            console.print(f"[bold red]ERROR:[/bold red] ")     # no use for now.
            self.print_usage(self.get_current_command())
        
        # Invalid arguments.
        elif match := re.search(r"unrecognized arguments: (.+)", message):
            invalid_item = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Invalid option: '{invalid_item}'")
            self.suggest_options(self.get_current_command(), invalid_item)
        
        # Missing required arguments.
        elif match := re.search(r"the following arguments are required: (.+)", message):
            missing_args = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Missing argument: '{missing_args}'")
            self.print_usage(self.get_current_command())

        # Expected one or more arguments.
        elif match := re.search(r"argument (.+): expected one argument", message):
            missing_arg_info = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Expected an argument for '{missing_arg_info}'.")
            self.print_usage(self.get_current_command())
        
        else:
            return super().error(message)

        raise SystemExit(2)


    def suggest_commands(self, invalid_command):
        commands = list(self._commands.keys())
        match = process.extractOne(invalid_command, commands, scorer=fuzz.ratio)

        if match and match[1] >= 80:    # 80 as default threshold.
            console.print(f"Did you mean [yellow]'{match[0]}'[/yellow]?")
        else:
            self.print_usage()


    def suggest_options(self, command, invalid_option):
        options = self.get_command_options(command)
        match = process.extractOne(invalid_option, options, scorer=fuzz.ratio)

        if match and match[1] >= 80:    # 80 as default threshold.
            console.print(f"Did you mean [yellow]'{match[0]}'[/yellow]?")
        else:
            self.print_usage(command)
