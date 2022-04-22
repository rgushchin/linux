#!/usr/bin/env python3
#
# Copyright (C) 2022 Roman Gushchin <roman.gushchin@linux.dev>
# Copyright (C) 2022 Meta

import os
import argparse
import sys


def scan_cgroups(cgroup_root):
    cgroups = {}

    for root, subdirs, _ in os.walk(cgroup_root):
        for cgroup in subdirs:
            path = os.path.join(root, cgroup)
            ino = os.stat(path).st_ino
            cgroups[ino] = path

    # (memcg ino, path)
    return cgroups


def scan_shrinkers(shrinker_debugfs):
    shrinkers = []

    for root, subdirs, _ in os.walk(shrinker_debugfs):
        for shrinker in subdirs:
            count_memcg_path = os.path.join(root, shrinker, "count_memcg")
            try:
                with open(count_memcg_path) as f:
                    for line in f.readlines():
                        items = line.split(' ')
                        ino = int(items[0])
                        shrinkers.append((int(items[1]), shrinker, ino))
            except FileNotFoundError:
                count_path = os.path.join(root, shrinker, "count")
                with open(count_path) as f:
                    shrinkers.append((int(f.readline()), shrinker, 0))

    # (count, shrinker, memcg ino)
    return shrinkers


def main():
    cgroups = scan_cgroups("/sys/fs/cgroup/")
    shrinkers = scan_shrinkers("/sys/kernel/debug/shrinker/")
    shrinkers = sorted(shrinkers, reverse = True, key = lambda x: x[0])

    for s in shrinkers:
        count = s[0]
        name = s[1]
        ino = s[2]

        if count == 0:
            break

        if ino == 0 or ino == 1:
            cg = "/"
        else:
            try:
                cg = cgroups[ino]
            except KeyError:
                cg = "unknown (%d)" % ino

        print("%-8s %-20s %s" % (count, name, cg))


if __name__ == '__main__':
    main()
