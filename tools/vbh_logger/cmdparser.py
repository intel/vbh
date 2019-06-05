import argparse


def hex_to_int(x):
    return int(x, 0)

class CmdParser:
    def __init__(self):
        pass

    @staticmethod
    def parse_cmd(script, actions):
        parent_parser = argparse.ArgumentParser()
        parent_parser.add_argument('--log', action='store_true', dest='log')
        parent_parser.add_argument('--policy', action='store', dest='policy', nargs='*')

        args1 = parent_parser.parse_args()

        print(args1)

        print(script)
        print(actions)

        return args1

    @staticmethod
    def parse_cmd_sp():
        parser = argparse.ArgumentParser()

        #parser.add_argument('--log', action='store_true', dest='log')
        parser.add_argument('--policy', action='append', dest='policies', nargs='*')

        exclusive_cmd = parser.add_argument_group('exclusive command')
        exclusive_grp = exclusive_cmd.add_mutually_exclusive_group()
        exclusive_grp.add_argument('--log', action='store_true', dest='log')
        exclusive_grp.add_argument('--script', action='store_true', dest='script')

        subparsers = parser.add_subparsers()

        parser_cr_write = subparsers.add_parser('cr_write')
        parser_cr_write.add_argument('cr', action='store', type=hex_to_int)
        parser_cr_write.add_argument('mask', action='store', type=hex_to_int)
        parser_cr_write.add_argument('action', type=str, choices=['enable', 'disable'])

        parser_msr_write = subparsers.add_parser('msr_write')
        parser_msr_write.add_argument('msr', action='store', type=hex_to_int)
        parser_msr_write.add_argument('enable', action='store_true')

        parser_ept_prot = subparsers.add_parser('ept_protection')
        parser_ept_prot.add_argument('mem', action='store', type=str)
        parser_ept_prot.add_argument('prot', action='store', type=hex_to_int)

        commands = parser.parse_args()

        return commands