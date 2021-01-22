import yaml

class YamlElement:
    def __init__(self, content, tag):
        self.content = content
        self.tag = tag

def elem_constructor(tag, loader, node):
    try:
        value = loader.construct_scalar(node)
    except:
        try:
            value = loader.construct_sequence(node)
        except:
            value = loader.construct_mapping(node)
    return YamlElement(value, tag)

def get_elem_constructor(tag):
    return lambda loader, node: elem_constructor(tag, loader, node)

terms = ['!Not', '!Equals', '!If', '!Ref', '!Sub', '!GetAtt', '!And', '!Condition',
        '!Select', '!Split', '!FindInMap', '!Join', '!ImportValue', '!GetAZs',
        '!Base64']

for term in terms:
    yaml.add_constructor(term, get_elem_constructor(term))
