class SecurityWarning:
    def __init__(self, node, message):
        self.node = node
        self.message = message

    def __eq__(self, other):
        return self.node.get_id() == other.node.get_id()

class SecurityWarningEmpty(SecurityWarning):
    def __init__(self, node):
        SecurityWarning.__init__(self, node, '{} is accessible at a time it doesn\'t exist'.format(node))

class SecurityContext:
    def __init__(self, name):
        self.name = name

    def is_less_secure_than(self, other):
        raise Exception('not implemented')

    def is_more_secure_than(self, other):
        raise Exception('not implemented')

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return self.name == other.name

class SecurityNone(SecurityContext):
    def __init__(self):
        SecurityContext.__init__(self, "None")

    def is_less_secure_than(self, other):
        return True

    def is_more_secure_than(self, other):
        return isinstance(other, SecurityNone)

class SecurityInaccessible(SecurityContext):
    def __init__(self):
        SecurityContext.__init__(self,"Inaccessible")

    def is_less_secure_than(self, other):
        return isinstance(other, SecurityInaccessible)

    def is_more_secure_than(self, other):
        return True

class SecurityModule(SecurityContext):
    def __init__(self, name):
        SecurityContext.__init__(self,name)

    def is_less_secure_than(self, other):
        if isinstance(other, SecurityModule):
            return self == other
        else:
            return other.is_more_secure_than(self)

    def is_more_secure_than(self, other):
        if isinstance(other, SecurityModule):
            return self == other
        else:
            return other.is_less_secure_than(self)

class SecurityAnd(SecurityContext):
    def __init__(self, c1, c2):
        SecurityContext.__init__(self, "And")
        self.c1 = c1
        self.c2 = c2

    def is_less_secure_than(self, other):
        compare1 = self.c1.is_less_secure_than(other)
        compare2 = self.c2.is_less_secure_than(other)
        return compare1 and compare2

    def is_more_secure_than(self, other):
        compare1 = self.c1.is_more_secure_than(other)
        compare2 = self.c2.is_more_secure_than(other)
        return compare1 or compare2

    def __repr__(self):
        return '({} and {})'.format(self.c1, self.c2)

class SecurityOr(SecurityContext):
    def __init__(self, c1, c2):
        SecurityContext.__init__(self, "Or")
        self.c1 = c1
        self.c2 = c2

    def is_less_secure_than(self, other):
        compare1 = self.c1.is_less_secure_than(other)
        compare2 = self.c2.is_less_secure_than(other)
        return compare1 or compare2

    def is_more_secure_than(self, other):
        compare1 = self.c1.is_more_secure_than(other)
        compare2 = self.c2.is_more_secure_than(other)
        return compare1 and compare2

    def __repr__(self):
        return '({} or {})'.format(self.c1, self.c2)
