# Adapted from https://github.com/benbc/cloud-formation-viz under
# the expat (MIT) license.

import sys
import json
import yaml
import datetime
import collections
from numbers import Number

from .dataflow import RootResource, EmptyResource, INITIAL, TARGET
from .cloudformation_graph import get_graph
from .cloudformation_types import *
from .cloudformation_yaml import *

class CloudFormationLoader:
    def __init__(self, file, label=None):
        self.file = file
        self.label = label

        template = self.open_cfn()
        if 'resources' in template:
            template = template['resources']
        if 'Resources' in template:
            resources = template['Resources']
        else:
            print("Warning: could not find CloudFormation resources in provided file: {}".format(self.file))
            resources = []
        self.nodes = [CloudFormationLoader.create_node(node, resources[node], label)
                        for node in resources]
        self.nodes = [x for x in self.nodes if x is not None]

    def create_graph(self):
        (nodes, edges, deps, sec, containers) = self.extract_graph(self.nodes)
        return get_graph(nodes, edges, deps, sec, containers)

    def create_upgrade_graph(self, other):
        """
        create an upgrade graph when this is the initial sTARGETtate and other is the
        target state.
        """
        nodes = [x for x in self.nodes]
        othernodes = []

        # Add other node only if configuration is different
        for node in other.nodes:
            counterpart = None

            for x in self.nodes:
                if x.get_id() == node.get_id():
                    counterpart = x

            if counterpart is not None:
                if counterpart.original_conf == node.original_conf:
                    continue

            nodes.append(node)
            othernodes.append(node)

        (nodes, edges, deps, sec, containers) = self.extract_graph(nodes)

        # Add empty nodes when they don't exist in the other state
        for n in self.nodes:
            same = False
            for nn in other.nodes:
                if nn.get_id() == n.get_id():
                    same = True
            if not same:
                r = EmptyResource(n.get_id(), n.get_name())
                r.set_origin(TARGET)
                nodes.append(r)


        for n in other.nodes:
            same = False
            for nn in self.nodes:
                if nn.get_id() == n.get_id():
                    same = True
            if not same:
                r = EmptyResource(n.get_id(), n.get_name())
                r.set_origin(INITIAL)
                nodes.append(r)

        return get_graph(nodes, edges, deps, sec, containers)

    def open_cfn(self):
        with open(self.file) as h:
            if any(extension in self.file for extension in ['.yml', '.yaml']):
                template = yaml.load(h.read(), Loader=yaml.Loader)
                template = self.templatize_yaml(template)
            else:
                template = json.load(h)
        return template

    @staticmethod
    def templatize_yaml(elem):
        if isinstance(elem, dict):
            for k, v in elem.items():
                elem[k] = CloudFormationLoader.templatize_yaml(v)
            return elem
        elif isinstance(elem, list):
            return [CloudFormationLoader.templatize_yaml(e) for e in elem]
        elif isinstance(elem, str):
            return elem
        elif isinstance(elem, bool):
            return elem
        elif isinstance(elem, Number):
            return elem
        elif isinstance(elem, datetime.date):
            return elem
        elif isinstance(elem, YamlElement):
            return {elem.tag: CloudFormationLoader.templatize_yaml(elem.content)}
        elif elem is None:
            return []
        else:
            raise AssertionError('Unexpected type: %s' % elem)

    @staticmethod
    def create_node(name, details, label):
        etype = None
        if 'Type' in details:
            etype = details['Type']

        if etype is None:
            print("Warning: type of {} not found".format(name), file=sys.stderr)
            return None

        node = None
        if etype in KNOWN_TYPES:
            node_type = KNOWN_TYPES[etype]
            node = AbstractNode(name, name, node_type, details, label)
        else:
            if not etype in IGNORED_TYPES:
                print("Warning: type {} not supported".format(etype), file=sys.stderr)
            return None
        return node

    @staticmethod
    def extract_graph(nodes):
        # create Resource objects
        nodes = [x.get_node() for x in nodes]
        
        # find edges
        edges = []
        for node in nodes:
            edges.extend(node.get_original_type().get_edges(node))

        # find dependencies
        deps = []
        for node in nodes:
            if node.get_original_type().origin == TARGET:
                deps.extend(node.get_original_type().get_deps(node))

        # find security relations
        sec = []
        for node in nodes:
            sec.extend(node.get_original_type().get_security_edges(node))

        # put them in a nicer structure security-node => {'from': list of from, 'to': list of to}.
        security_relations = {}
        for s in sec:
            secnode = s['security']
            if not secnode in security_relations:
                security_relations[secnode] = {'from': [], 'to': []}
            if 'from' in s:
                security_relations[secnode]['from'].append(s['from'])
            if 'to' in s:
                security_relations[secnode]['to'].append(s['to'])

        # find content of container resources
        node_content = []
        for node in nodes:
            node_content.extend(node.get_original_type().get_content(node))

        # put them in a nice structure container => list of content
        containers = {}
        for c in node_content:
            container = c['container']
            content = c['has']
            if not container in containers:
                containers[container] = []
            containers[container].append(content)

        return (nodes, edges, deps, security_relations, containers)
