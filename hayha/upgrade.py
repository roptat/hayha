from .dataflow import *
from .security import *

def find_by_id(elements, id):
    """
    Searches elements for nodes with `id`.  When no node is found, return None.
    When one node is found, return it.  When two nodes are found, return a
    ChoiceResource that has both.
    """
    results = []
    for x in elements:
        if x.get_id() == id:
            results.append(x)

    if results == []:
        return None

    if len(results) == 1:
        return results[0]
    else:
        if results[0].get_origin() == INITIAL:
            return ChoiceResource(results[0], results[1])
        else:
            return ChoiceResource(results[1], results[0])

def copy_graph(nodes, root):
    """Create a copy of a graph"""
    newnodes = {}

    for node in nodes:
        newnodes[node] = copy_node(node)

    for node in newnodes:
        if isinstance(node, ChoiceResource):
            newnodes[node].r1 = newnodes[node.r1]
            newnodes[node].r2 = newnodes[node.r2]

    for node in newnodes:
        new_node = newnodes[node]
        for n in newnodes:
            newnodes[n].replace_child(node, new_node)
            newnodes[n].replace_dep(node, new_node)

    nodes = [newnodes[x] for x in newnodes]
    return (nodes, newnodes[root])

def get_choice_of(nodes, node):
    for n in nodes:
        if isinstance(n, ChoiceResource) and (n.r1 == node or n.r2 == node):
            return n
    return node

def remove_in_graph(nodes, n):
    """
    In nodes (the flattened graph), remove any reference to n.  When n is a
    SecurityResource, make sure no dataflow bypasses it directly.
    """
    for node in nodes:
        node.remove_child(n)
        node.remove_dependency(n)

    nodes_with_id = find_by_id(nodes, n.get_id())
    other_node = None
    if isinstance(nodes_with_id, ChoiceResource):
        if nodes_with_id.r1 == n:
            other_node = nodes_with_id.r2
        else:
            other_node = nodes_with_id.r1

    if isinstance(other_node, SecurityResource):
        parents = [x for x in nodes if x.has_child(other_node)]
        for p in parents:
            for c in other_node.get_children():
                p.remove_child(c)

def split_dependency(g, nodes, f, t):
    """
    Split a graph in three upgrade graphs by splitting the dependency from f
    to t in graph g.

    If g has the following: f -> f' and t -> t', we create three graphs where
    we have only:
    - f and t
    - f and t'
    - f' and t'
    (f' and t cannot happen, because f is only upgraded after t).
    """
    f.remove_dependency(t)

    (nodes, g) = copy_graph(nodes, g)
    (nodes1, g1) = copy_graph(nodes, g)
    (nodes2, g2) = copy_graph(nodes, g)
    result = []

    node_f = find_by_id(nodes, f.get_id())
    node_t = find_by_id(nodes, t.get_id())

    if node_f == None or node_t == None:
        return [(nodes, g)]

    # build the first graph: f and t
    if (isinstance(node_f, ChoiceResource) or node_f.get_origin() == INITIAL) \
            and (isinstance(node_t, ChoiceResource) or node_t.get_origin() == INITIAL):
        if isinstance(node_f, ChoiceResource):
            remove_in_graph(nodes, node_f.r2)
            nodes.remove(node_f.r2)
        if isinstance(node_t, ChoiceResource):
            remove_in_graph(nodes, node_t.r2)
            nodes.remove(node_t.r2)
        result.append((nodes, g))

    # build the second graph: f and t'
    node_f = find_by_id(nodes1, f.get_id())
    node_t = find_by_id(nodes1, t.get_id())

    if (isinstance(node_f, ChoiceResource) or node_f.get_origin() == INITIAL) \
            and (isinstance(node_t, ChoiceResource) or node_t.get_origin() == TARGET):
        if isinstance(node_f, ChoiceResource):
            remove_in_graph(nodes1, node_f.r2)
            nodes1.remove(node_f.r2)
        if isinstance(node_t, ChoiceResource):
            remove_in_graph(nodes1, node_t.r1)
            nodes1.remove(node_t.r1)
        result.append((nodes1, g1))

    # build the third graph: f' and t'
    node_f = find_by_id(nodes2, f.get_id())
    node_t = find_by_id(nodes2, t.get_id())

    if (isinstance(node_f, ChoiceResource) or node_f.get_origin() == TARGET) \
            and (isinstance(node_t, ChoiceResource) or node_t.get_origin() == TARGET):
        if isinstance(node_f, ChoiceResource):
            remove_in_graph(nodes2, node_f.r1)
            nodes2.remove(node_f.r1)
        if isinstance(node_t, ChoiceResource):
            remove_in_graph(nodes2, node_t.r1)
            nodes2.remove(node_t.r1)
        result.append((nodes2, g2))

    return result

def split_dependencies(nodes, root):
    """Remove dependencies in a graph by splitting it into more dataflow
graphs that represents the different possibilities.  Returns a list of graphs"""
    for n in nodes:
        deps = n.get_dependencies()
        if len(deps) == 0:
            continue

        result = []
        for (ns, graph) in split_dependency(root, nodes, n, deps[0]):
            result.extend(split_dependencies(ns, graph))
        return result
    return [(nodes, root)]

def check_empty_permission(node):
    if SecurityInaccessible().is_less_secure_than(node.security):
        return []
    return [SecurityWarningEmpty(node)]

def check_node_permission(node, nodes):
    n = find_by_id(nodes, node.get_id())
    if n is None:
        raise Exception("n is None, nodes are {} (for id {})".format(nodes, node))

    # We silence warnings about security resources
    if n.security.is_less_secure_than(node.security) or isinstance(n, SecurityResource):
        return []
    else:
        return [SecurityWarning(node, '{} is not sufficiently protected, it \
needs at least {} and is protected by {} during upgrade.  Add DependsOn \
properties to ensure correct security.'.format(node, n.security, node.security))]

def check_permission(graph_before, upgrade_graph, graph_after):
    nodes = upgrade_graph.flatten()
    before_nodes = graph_before.flatten()
    after_nodes = graph_after.flatten()
    result = []
    for node in nodes:
        r1 = None
        r2 = None
        if isinstance(node, ChoiceResource):
            r1 = node.r1
            r2 = node.r2
        elif node.get_origin() == INITIAL:
            r1 = node
        elif node.get_origin() == TARGET:
            r2 = node
        else:
            continue

        if isinstance(r1, EmptyResource):
            result.extend(check_empty_permission(r1))
        elif r1 is not None:
            result.extend(check_node_permission(r1, before_nodes))

        if isinstance(r2, EmptyResource):
            result.extend(check_empty_permission(r2))
        elif r2 is not None:
            result.extend(check_node_permission(r2, after_nodes))
    return result
