#!/usr/bin/python3

from core.core_utils import start_core, start_helper
from core.pastebin_utils import pastebin_listen

def run(*script_args):
    if len(script_args) != 1:
        print('You must define a single service to start.')
        sys.exit(1)

    if script_args[0].lower() == 'core':
        print('Starting core service...')
        start_core()

    if script_args[0].lower() == 'helper':
        print('Starting helper service...')
        start_helper()

    if script_args[0].lower() == 'pastebin':
        print('Starting PasteBin service...')
        pastebin_listen()
