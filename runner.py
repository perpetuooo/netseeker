import argparse

parser = argparse.ArgumentParser()
parser.add_argument('echo', help="Echos the given string.")

args: argparse.Namespace = parser.parse_args()


print(args.echo)


if __name__ == '__main__':
    pass