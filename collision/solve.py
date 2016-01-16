#!/usr/bin/env python

import angr

def main():
    project = angr.Project("./a.out")

    argv1 = angr.claripy.BVS("argv1",20*8)
    initial_state = project.factory.path(args=["./a.out", argv1])

    pg = project.factory.path_group(initial_state)

    pg.explore(find=0x4006d4)

    found = pg.found[0]
    solution = found.state.se.any_str(argv1)

    return solution

if __name__ == '__main__':
    print(repr(main()))
