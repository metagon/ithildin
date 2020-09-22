#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sys import exit
from sc3a.interfaces.cli import main, parse_cli_args

if __name__ == "__main__":
    main(parse_cli_args())
    exit(0)
