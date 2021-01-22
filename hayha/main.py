from argparse import ArgumentParser
from .cloudformation_load import CloudFormationLoader
from .upgrade import split_dependencies, check_permission
from .security import SecurityNone
from .dataflow import INITIAL, TARGET
import sys

def uniq(lst):
    result = []
    for x in lst:
        if x not in result:
            result.append(x)
    return result

def main(args):
    parser = ArgumentParser(description='Check a CloudFormation upgrade plan \
for possible sniping attacks.')
    parser.add_argument('action', metavar="ACTION", default="check",
            help="action to be taken: check or graph")
    parser.add_argument('-i', '--initial', required=True,
            help="a json or yaml file corresponding to the initial state if \
there is a target file, or any other file if there is no target file.")
    parser.add_argument('-t', '--target',
            help="a json or yaml file corresponding to the target state.")
    args = parser.parse_args(args)

    if args.action == 'check':
        if args.target is None:
            print("target file is required.")
            exit(1)
        initial_state = CloudFormationLoader(args.initial, INITIAL)
        target_state  = CloudFormationLoader(args.target, TARGET)
        (_,g1) = initial_state.create_graph()
        (_,g2) = target_state.create_graph()

        g1.set_security(SecurityNone())
        g2.set_security(SecurityNone())
        g1.compute_security()
        g2.compute_security()

        # re-read the files to prevent object copy
        initial_state = CloudFormationLoader(args.initial, INITIAL)
        target_state  = CloudFormationLoader(args.target, TARGET)
        (nodes, u) = initial_state.create_upgrade_graph(target_state)

        splits = split_dependencies(nodes, u)
        results = []
        for (nodes, u) in splits:
            u.set_security(SecurityNone())
            u.compute_security()
            results.extend(check_permission(g1, u, g2))
        results = uniq(results)
        if len(results) == 0:
            print("No issues were found!")
        else:
            print("{} issues were found:".format(len(results)))
            for r in results:
                print(r.message)
            #exit(1)
        return (sum(map(lambda n : len(n.dependencies), g1.flatten())), len(g1.flatten()))
    elif args.action == 'graph':
        initial_state = CloudFormationLoader(args.initial, INITIAL)
        if args.target is not None:
            target_state  = CloudFormationLoader(args.target, TARGET)
            (_, u) = initial_state.create_upgrade_graph(target_state)
            u.set_security(SecurityNone())
            u.compute_security()
            u.render()
        else:
            (_, g) = initial_state.create_graph()
            g.set_security(SecurityNone())
            g.compute_security()
            g.render()
    else:
        print("Unknown action {}.".format(args.action))
        parser.print_help()
        exit(1)

def cli():
    main(sys.argv[1:])

if __name__ == '__main__':
    main(sys.argv[1:])
