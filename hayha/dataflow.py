from .security import *

INITIAL = 1
TARGET  = 2

def make_or_security(a, b):
    if a.is_less_secure_than(b):
        return a
    elif b.is_less_secure_than(a):
        return b
    else:
        return SecurityOr(a, b)

def make_and_security(a, b):
    if a.is_less_secure_than(b):
        return b
    elif b.is_less_secure_than(a):
        return a
    else:
        return SecurityAnd(a, b)

class Resource:
    def __init__(self, id, name, children=None, dependencies=None, original_type=None):
        self.id = id
        self.name = name
        self.children = [] if children is None else [x for x in children]
        self.dependencies = [] if dependencies is None else [x for x in dependencies]
        self.security = SecurityInaccessible()
        self.render_id = None
        self.original_type = original_type
        self.original_conf = None
        self.origin = None

    def set_origin(self, origin):
        self.origin = origin

    def get_origin(self):
        return self.origin

    def copy(self):
        return Resource(self.id, self.name, self.children, self.dependencies, self.original_type)

    def get_original_type(self):
        return self.original_type

    def set_original_type(self, t):
        self.original_type = t

    def add_child(self, child):
        if not child in self.children:
            self.children.append(child)

    def has_child(self, child):
        return child in self.children

    def remove_child(self, child):
        if child in self.children:
            self.children.remove(child)

    def get_children(self):
        return self.children

    def replace_child(self, child, to):
        if to in self.children:
            self.children = [x for x in self.children if x != child]
        else:
            self.children = [to if x == child else x for x in self.children]

    def replace_dep(self, dep, to):
        if to in self.dependencies:
            self.dependencies = [x for x in self.dependencies if x != dep]
        else:
            self.dependencies = [to if x == dep else x for x in self.dependencies]

    def add_dependency(self, dep):
        if not dep in self.dependencies:
            self.dependencies.append(dep)

    def has_dependency(self, dep):
        return dep in self.dependencies

    def remove_dependency(self, dep):
        if dep in self.dependencies:
            self.dependencies.remove(dep)

    def get_dependencies(self):
        return self.dependencies

    def get_name(self):
        return self.name

    def get_id(self):
        return self.id

    def set_security(self, security):
        self.security = security

    def update_security(self, security):
        self.security = make_or_security(self.security, security)

    def compute_security(self):
        for child in self.children:
            security_before = child.security
            child.update_security(self.security)
            if child.security.is_less_secure_than(security_before):
                if not security_before.is_less_secure_than(child.security):
                    child.compute_security()

    def render(self):
        print('digraph {')
        print('  compound=true;')
        self.render_edges('n')
        self.clean_render()
        print('}')

    def render_edges(self, id):
        if self.render_id is None:
            self.render_id = id
            self.render_node()
            n = 0
            for child in self.children:
                n = n + 1
                child_id = id + str(n)
                child_ids = child.render_edges(child_id)
                if isinstance(child_ids, list):
                    for child_id in child_ids:
                        print('  {} -> {} [lhead=cluster_{}];'.format(id, child_id, child.render_id))
                else:
                    print('  {} -> {};'.format(id, child_ids))
        return self.render_id

    def render_node(self):
        print('  {} [label="{}({})"];'.format(self.render_id, self.security, self.name))

    def clean_render(self):
        if self.render_id is not None:
            self.render_id = None
            for child in self.children:
                child.clean_render()

    def flatten(self, result=None):
        result = [] if result is None else result
        if self in result:
            return result
        result.append(self)
        for c in self.children:
            result = c.flatten(result)
        return result

    def __repr__(self):
        return '<Resource {}>'.format(self.name)

class ChoiceResource(Resource):
    def __init__(self, r1, r2):
        Resource.__init__(self, r1.id, r1.name)
        self.r1 = r1
        self.r2 = r2

    def copy(self):
        return ChoiceResource(self.r1, self.r2)

    def replace_child(self, child, to):
        self.r1.replace_child(child, to)
        self.r2.replace_child(child, to)

    def replace_dep(self, dep, to):
        self.r1.replace_dep(dep, to)
        self.r2.replace_dep(dep, to)

    def update_security(self, security):
        Resource.update_security(self, security)
        self.r1.update_security(security)
        self.r2.update_security(security)

    def compute_security(self):
        self.r1.compute_security()
        self.r2.compute_security()

    def render_node(self):
        print('  subgraph cluster_%s {' % self.render_id)
        id1 = self.r1.render_id
        id2 = self.r2.render_id
        print('  {} -> {} [color=blue];'.format(id1, id2))
        print('  {rank=same;%s;%s}' % (id1, id2))
        print('  }')

    def render_edges(self, id):
        if self.render_id is None:
            self.render_id = id
            self.r1.render_edges(id+'l')
            self.r2.render_edges(id+'r')
            self.render_node()
        return [self.r1.render_id]

    def flatten(self, result=None):
        result = [] if result is None else result
        if self in result:
            return result
        result.append(self)
        result = self.r1.flatten(result)
        result = self.r2.flatten(result)
        return result

    def __repl__(self):
        return '<ChoiceResource {}>'.format(self.name)

class SecurityResource(Resource):
    def __init__(self, id, name, children=None, dependencies=None,
            security=None, original_type=None):
        Resource.__init__(self, id, name, children, dependencies, original_type)
        if security is None:
            security = SecurityModule(name)
        self.self_security = security

    def copy(self):
        return SecurityResource(self.id, self.name, self.children,
                self.dependencies, self.self_security, self.original_type)

    def update_security(self, security):
        Resource.update_security(self, security)
        self.security = make_and_security(self.security, self.self_security)

    def render_node(self):
        print('  {} [label={}, color=red];'.format(self.render_id, self.name))

class EmptyResource(Resource):
    def __init__(self, id, name):
        Resource.__init__(self, id, name)

    def render_node(self):
        print('  {} [label={}, color=gray];'.format(self.render_id, self.name))

    def copy(self):
        return EmptyResource(self.id, self.name)

class RootResource(Resource):
    def __init__(self):
        Resource.__init__(self, "Web", "Web")

    def render_node(self):
        print('  {} [label={}, fillcolor=gray, style=filled];'.format(self.render_id, self.name))

    def copy(self):
        r = RootResource()
        r.children = [x for x in self.children]
        r.dependencies = [x for x in self.dependencies]
        return r

def copy_node(node):
    new_node = node.copy()
    new_node.set_origin(node.get_origin())
    return new_node
