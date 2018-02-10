#!/usr/bin/env python
# -*- coding:utf-8 -*-
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import
from __future__ import division

import os
import io


def count_source(path, ext):
    total = 0
    for root, dirs, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith(ext):
                filepath = os.path.join(root, filename)
                with io.open(filepath, "r", encoding = "utf-8") as f:
                    lines = len(f.readlines())
                    print(filepath, ":", lines)
                    total += lines
    return total


def main():
    total = 0
    total += count_source("src", ".cpp")
    total += count_source("include", ".h")
    total += count_source("tests", ".cpp")
    total += count_source("contrib", ".cpp")
    total += count_source("contrib", ".h")
    print("total:", total)


if __name__ == "__main__":
    main()
