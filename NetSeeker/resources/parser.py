import re
import sys
import argparse
from rich import box
from rich.table import Table
from rich.panel import Panel
from rich.padding import Padding
from rapidfuzz import process, fuzz

from resources import console


class NetSeekerArgumentParser(argparse.ArgumentParser):
    @property
    def _commands(self):
        # Cache commands to avoid re-parsing.
        if not hasattr(self, '_cached_commands_dict'):
            self._cached_commands_dict = {}

            # Parse through all subparsers.
            subparser_action = next((action for action in self._actions if isinstance(action, argparse._SubParsersAction)), None)
            
            if not subparser_action:
                return self._cached_commands_dict

            for cmd, subparser in subparser_action.choices.items():
                self._cached_commands_dict[cmd] = {}

                for action in subparser._actions:
                    # Skip actions.
                    if isinstance(action, argparse._SubParsersAction):
                        continue

                    dest = action.dest
                    
                    if dest == argparse.SUPPRESS:
                        continue    
                    
                    # Determine argument type
                    if action.type:
                        arg_type = action.type.__name__.upper()
                    elif action.nargs is not None:
                        
                        if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction): # Boolean values.
                            arg_type = " "
                        elif action.option_strings: # Optional argument, probably a boolean also.
                             arg_type = " " 
                        else: # Positional argument.
                            arg_type = cmd.upper()

                    # Default
                    else:
                        arg_type = "TEXT"

                    self._cached_commands_dict[cmd][dest] = {
                        "options": action.option_strings,
                        "default": action.default,
                        "help": action.help or "",
                        "type": arg_type,
                    }

        return self._cached_commands_dict


    def get_current_command(self):
        if not hasattr(self, '_current_command'):
            self._current_command = None

        commands = self._commands.keys()
        
        for arg in sys.argv[1:]:
            if arg in commands:
                self._current_command = arg

    def print_help(self, command=None, file=None):
        if file is None:
            file = sys.stdout
        # return super().print_help(file)

        # Create and configure tables.
        arguments_table = Table(box=None, show_header=False, show_lines=False, padding=(0,1))
        options_table = Table(box=None, show_header=False, show_lines=False, padding=(0,1))
        options_table.add_column(style="bold blue")  # Options.
        options_table.add_column(style="bold yellow")  # Type.
        options_table.add_column()  # Help & Default Value.
        # Create and configure panels.
        arguments_panel = Panel(
            Padding(arguments_table, (0, 1)),
            title="Arguments",
            # border_style="dim",
            title_align="left",
            expand=True,
            box=box.SQUARE,
        )
        options_panel = Panel(
            Padding(options_table, (0, 1)),
            title="Options",
            # border_style="dim",
            title_align="left",
            expand=True,
            box=box.SQUARE,
        )

        # As much as I want to make the help message system fully dynamic, I cant think of a way to make it work while being flexible.
        match command:
            case "portscan":
                console.print("Usage: netseeker portscan [TARGET] [OPTIONS]")
                console.print("Scans a target IP address or domain for open TCP and/or UDP ports.")
                console.print("Example: netseeker portscan 192.168.1.100 --ports 25,53,8080 --timeout 3")
            case "netscan":
                console.print("Usage: netseeker netscan [TARGET] [OPTIONS]")
                console.print("Discover hosts on a network (ARP + ICMP for local networks and ICMP + TCP SYN for remote).")
                console.print("Example: netseeker netscan 192.168.1.0/24 --tcp-syn --verbose")
            case "traceroute":
                console.print("Usage: netseeker traceroute [TARGET] [OPTIONS]")
                console.print("Traces the network path that IP packets take to reach a target host.")
                console.print("Example: netseeker traceroute google.com --max-hops 50 --generate-map")
            case "sdenum":
                console.print("Usage: netseeker sdenum [DOMAIN] [OPTIONS]")
                console.print("Discover subdomains by recursive brute forcing (A, CNAME and NS records by default).")
                console.print("Example: netseeker sdenum test.com --wordilist path/to/your/wordlist.txt --output")
            case _:   # General help message.
                arguments_panel.title = "Commands"
                arguments_table.add_column()
                options_table.add_row(f"--help / -h    ", "", "    Show this help message and exit.")
                arguments_table.add_row("portscan            ", "Scans target for open TCP/UDP ports.")
                arguments_table.add_row("netscan            ", "Discover hosts on a network.")
                arguments_table.add_row("traceroute            ", "Trace the network path to a target.")
                arguments_table.add_row("sdenum            ", "Subdomain enumeration with recursive brute force.")

                console.print("Usage: netseeker COMMAND [ARGS] [OPTIONS]")
                console.print()
                console.print(arguments_panel)
                console.print()
                console.print(options_panel)

                raise SystemExit
        
        console.print()

        for arg, meta in self._cached_commands_dict[command].items():
            # Positional args.
            if not meta['options']:
                arguments_table.add_row(f"{arg}   [{arg.upper()}]   {meta['help']} Default: {meta['default']}")
                continue
            
            # Other options.
            options_table.add_row(f"{" / ".join(meta['options'])}    ", meta['type'], f"    {meta['help']} Default: {meta['default']}")

        console.print(arguments_panel)
        console.print()
        console.print(options_panel)

        raise SystemExit

    
    def print_usage(self, command=None, file=None):
        if file is None:
            file = sys.stdout

        commands = self._commands.keys()
            
        if command in commands:
            console.print(f"Try [yellow]'netseeker {command} --help'[/yellow] for more information.")
        else:
            console.print(f"Try [yellow]'netseeker --help'[/yellow] for more information.")

    
    def error(self, message):
        # return super().error(message)

        # Invalid command.
        if match := re.search(r"argument command: invalid choice: '([^']+)'", message):
            invalid_item = match.group(1)
            console.print(f"[bold red]ERROR:[/bold red] Invalid command: [bold]'{invalid_item}'[/bold]")
            self.suggest_commands(invalid_item)
        
        # Invalid choice (https://docs.python.org/3/library/argparse.html#choices).
        elif match := re.search(r"argument move: invalid choice: '([^']+)'", message):
            console.print(f"[bold red]ERROR:[/bold red] ")     # no use for now.
            self.print_usage(self._current_command)
        
        # Invalid arguments.
        elif match := re.search(r"unrecognized arguments: (.+)", message):
            invalid_item = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Invalid option: [bold]'{invalid_item}'[/bold]")
            self.suggest_options(self._current_command, invalid_item)
        
        # Missing required arguments.
        elif match := re.search(r"the following arguments are required: (.+)", message):
            missing_args = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Missing argument: [bold]'{missing_args}'[/bold]")
            self.print_usage(self.get_current_command())

        # Expected one or more arguments.
        elif match := re.search(r"argument (.+): expected one argument", message):
            missing_arg_info = match.group(1).strip()
            console.print(f"[bold red]ERROR:[/bold red] Expected an argument for [bold]'{missing_arg_info}'[/bold].")
            self.print_usage(self.get_current_command())
        
        else:
            return super().error(message)

        raise SystemExit(2)


    def suggest_commands(self, invalid_command):
        commands = list(self._commands.keys())
        match = process.extractOne(invalid_command, commands, scorer=fuzz.ratio)

        if match and match[1] >= 80:    # 80 as default threshold.
            console.print(f"Did you mean [yellow]{match[0]}[/yellow]?")
        else:
            self.print_usage()


    def suggest_options(self, command, invalid_option):
        for _, meta in self._cached_commands_dict[command].items():
            match = process.extractOne(invalid_option, meta['options'], scorer=fuzz.ratio)

            if match and match[1] >= 80:    # 80 as default threshold.
                console.print(f"Did you mean [yellow]{match[0]}[/yellow]?")
                return

        self.print_usage(command)
