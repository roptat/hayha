from .dataflow import RootResource, Resource, TARGET
import sys

def get_graph(nodes, edges, deps, sec, containers):
    """
    Return a graph from nodes and configurations.

    The list of nodes is a list of Resource objects with labels.  Edges is a list
    of (from, to) objects that reference a node or an identifier and correspond
    to direct flows.  Deps is a list of (from, to) objects that reference nodes
    and correspond to dependencies in the target configuration.  Sec contains
    dictionnary from identifiers or nodes to (from, to) objects that are lists
    of identifiers or nodes.  Containers are dictionnary from identifiers or nodes
    to a list of identifier or nodes.

    First, each edge is turned into a child in the graph.

    Then, sec is used to graft security nodes.

    Finaly, containers is used to expand container nodes' edges to their content.

    When a value is a node, only consider that node, otherwise consider all nodes
    with that identifier.
    """
    root = RootResource()
    nodes.append(root)
    # connect accessible nodes to the web
    for node in nodes:
        if node.get_original_type() is not None and \
                node.get_original_type().is_accessible():
            root.add_child(node)

    # Add children for each edge we collected before
    for edge in edges:
        parents = get_resource(nodes, edge['from'])
        children = get_resource(nodes, edge['to'])
        for node in parents:
            for child in children:
                node.add_child(child)

    # Same with dependencies
    for dep in deps:
        parents = get_resource(nodes, dep['from'])
        children = get_resource(nodes, dep['to'])
        for node in parents:
            for child in children:
                if node.get_origin() == TARGET and child.get_origin() == TARGET:
                    node.add_dependency(child)

    # Ensure containers only has Resource as keys and in values by creating more
    # entries if necessary.
    expanded_containers = {}
    for container in containers:
        for c in get_resource(nodes, container):
            if not c in expanded_containers:
                expanded_containers[c] = []
            for x in containers[container]:
                expanded_containers[c].extend(get_resource(nodes, x))

    # Same with sec
    expanded_sec = {}
    for security in sec:
        for s in get_resource(nodes, security):
            if not s in expanded_sec:
                expanded_sec[s] = {'from': [], 'to': []}
            for x in sec[security]['from']:
                expanded_sec[s]['from'].extend(get_resource(nodes, x))
            for x in sec[security]['to']:
                expanded_sec[s]['to'].extend(get_resource(nodes, x))

    nodes = move_security_nodes(nodes, expanded_sec, expanded_containers)
    nodes = move_container_nodes(nodes, expanded_containers)
    return (nodes, root)

def get_resource(nodes, identification):
    if isinstance(identification, Resource):
        return [identification]
    result = []
    for node in nodes:
        if node.get_id() == identification:
            result.append(node)
    return result

def move_security_nodes(nodes, sec, containers):
    # split security nodes into those who specify a "from" node and those who
    # don't.
    from_sec = {}
    to_sec = {}
    for s in sec:
        if sec[s]['from'] == []:
            if s.get_id() in to_sec:
                continue

            to_sec[s.get_id()] = {}
            for ss in sec:
                if ss.get_id() == s.get_id():
                    to_sec[s.get_id()][ss] = sec[ss]
        else:
            from_sec[s] = sec[s]
    # First graft those who do
    graft_security_nodes(nodes, from_sec, containers)

    # Then those who don't, removing edges that were grafted immediately
    for id in to_sec:
        graft_security_nodes(nodes, to_sec[id], containers)
    return nodes

def graft_security_nodes(nodes, sec, containers):
    """
    Move security resources in the graph to put them between requesters and
    protected resources.  Ex: when a Lambda is protected by a Role, the Role
    is put between the Internet and the Lambda (Internet -> Role -> Lambda).

    Only nodes from the 'from' are modified, unless there is no 'from', in
    which case all parent nodes are modified.

    When one of the nodes is a container, it refers it and its content.
    """
    # edges to remove after we grafted security resources
    obsolete_edges = []

    for sec_node in sec:
        to_nodes = sec[sec_node]['to']
        from_nodes = sec[sec_node]['from']

        # extend from and to nodes with content of container nodes
        for node in from_nodes:
            if node.get_original_type() is None:
                continue
            if node.get_original_type().is_container() and node in containers:
                from_nodes.extend(containers[node])

        for node in to_nodes:
            if node.get_original_type() is None:
                continue
            if node.get_original_type().is_container() and node in containers:
                to_nodes.extend(containers[node])

        # edges we need to graft the security resource onto.
        edges = []

        # If from_nodes is empty, we graft between the to nodes and any parent.
        if from_nodes == []:
            for node in to_nodes:
                for x in nodes:
                    if not x.has_child(node) or x in to_nodes:
                        continue
                    if x.get_id() == sec_node.get_id():
                        continue
                    edges.append({'from': x, 'to': node})
        # otherwise, we graft only between from nodes and to nodes.
        else:
            for from_node in from_nodes:
                for to_node in to_nodes:
                    if from_node.has_child(to_node):
                        edges.append({'from': from_node, 'to': to_node})

        for e in edges:
            to_node = e['to']
            from_node = e['from']
            from_node.add_child(sec_node)
            sec_node.add_child(to_node)
            obsolete_edges.append({'from': from_node, 'to': to_node, 'via': sec_node})

    for e in obsolete_edges:
        conditional_remove_edge(nodes, e)
    return nodes

def conditional_remove_edge(nodes, edge):
    good_children = [x for x in edge['from'].get_children() if x.get_id() == edge['via'].get_id()]
    if len(good_children) != len([x for x in nodes if x.get_id() == edge['via'].get_id()]):
        return

    for child in good_children:
        if not child.has_child(edge['to']):
            return

    edge['from'].remove_child(edge['to'])

def move_container_nodes(nodes, container):
    """
    Remove container resources in the graph by replacing them with their
    content.  Parents and children are copied over to content.
    """
    for c in container:
       parents = [x for x in nodes if x.has_child(c) and x != c]
       children = [ x for x in c.get_children() if x != c]

       for content in container[c]:
           if content == c:
               continue
           for child in children:
               content.add_child(child)
           for parent in parents:
               parent.add_child(content)

       for parent in parents:
           parent.remove_child(c)
    return nodes
