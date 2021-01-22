Häyhä
=====

Verifying CloudFormation deployments for intra-update sniping vulnerabilities.

Intra-update sniping vulnerabilities may happen during an update because of
ordering issues between individual component updates.  This tool is designed
to find and report such issues.

Installation
------------

Installing the tool is not necessary in order to run it.

### With Guix

You can install Häyhä with the [Guix](https://guix.gnu.org) package manager.
It can run on any existing Linux distribution, and is guaranteed to not
interact with its host distribution. Installing Guix is as simple as running
the [installation script](https://git.savannah.gnu.org/cgit/guix.git/plain/etc/guix-install.sh).
Once installed, you can run:

```bash
guix install `guix build -f guix.scm`
```

### With pip

You can also install using pip:

```bash
pip install .
```

Development Environment
-----------------------

To develop (and run) Häyhä, you need to install pyyaml.  An easy way to do so
is by using a Guix environment:

```bash
guix environment -l guix.scm
```

You may also want to install `graphviz` (for the `dot` command) and an image
viewer.

Usage
-----

You should run Häyhä before running an upgrade on your CloudFormation
infrastructure.  We suppose that you have a file that describes your
current infrastructure, as JSON or YAML, and another file that describes your
target (desired new) infrastructure, in one of these formats.

Häyhä needs a one of two commands: `graph` or `check` to run, and one or
two CloudFormation files, in JSON or YAML format.  The usage is the following:

```
usage: run.py [-h] -i INITIAL [-t TARGET] ACTION
```

You can use `-h` to show a short help message.  `ACTION` is one of `graph` or
`check`.  `-i` is for the initial file (or the only file to consider) and
`-t` for the target file (the upgrade).

### Graph

Häyhä is able to produce graphs for deployments that shows what a deployment
looks like in terms of a dataflow graph.  It will have a gray `web` node
from which requests can be made by users of your infrastructure.  A link
represents the possibility of a request from a node to another.  Red nodes
represent security resources that control the requests to make sure they are
authorized (firewall, authorizer, ...).

Each node contains the security level followed (in parenthesis) by the
name of the resource.

Häyhä can draw two kinds of graph: the graph of a deployment if you only provide
one file (whether initial or target) using the `-i` option or the upgrade graph
if you provide two files (the initial deployment to the `-i` option and the
target deployment to the `-t` option).

The upgrade graph represents every possible intermediate state during the
deployment of the target infrastructure, but does not take any dependency
into account.

This repository ships with two files, `cloud1.json` and `cloud2.json` that
correspond to two versions of a vulnerable infrastructure.  To run and
visualize the output, you can run:

```bash
python3 run.py graph -i cloud1.json | dot -Tpng -o graph.png
```

Or for an upgrade graph that shows the vulnerability:

```bash
python3 run.py graph -i cloud1.json -t cloud2.json | dot -Tpng -o graph.png
```

### Check

Häyhä is also able to check a planned upgrade of an infrastructure if you give
it two files, like this:

```bash
python3 run.py check -i cloud1.json -t cloud2.json
```

The output will tell you if a vulnerability is found.

### Possible Warnings

You might get a warning that some type is not supported.  Unfortunately the
tool relies on a mapping of types' configuration fields to an internal
representation.  There are many types of resources that can be used in an
infrastructure.  Even though we included the most current type of resources
in this version, there are still many unsupported types.  In that case, the
tool completely ignores the resource when building the graphs and checking
for vulnerabilities.

### Vulnerabilities

If Häyhä finds a vulnerability under the `check` command, it will report it
at the end.  To prevent clutter on the screen, we only report one issue for
each resource that has an issue, so after fixing issues, make sure to run the
tool again!

There is a vulnerability when a resource can be referenced at a time it does
not exist.  This can happen when your target infrastructure creates a new
resource and updates others to reference it.  If these other resources do not
depend on the new resource, they might be updated before and be vulnerable to
an attacker registering your new resource before you do.  The message will
look like this:

```
<Resource AuthorizerToBeSniped> is accessible at a time it doesn't exist
```

This can be solved by adding a dependency in every resource that references
it.  In the example, you can add a DependsOn property to `GreetingRequestPOST`
which references it and makes it required too early.  Alternatively, use
`!Ref` instead of `Ref` in `GreetingRequestPOST`'s  `AuthorizerId` field, as
it will implicitly create a dependency.

There is a vulnerability when a resource can be accessed with the wrong security
context.  The message will look like this:

```
<Resource GreetingRequestPOST> is not sufficiently protected, it needs at least
AuthorizerToBeSniped and is protected by None during upgrade.  Add DependsOn
properties to ensure correct security.
```

This means that there is a possible intermediate state in which your `GreetingRequestPOST`
is not correctly protected.  In fact, in at least one, it is not protected at
all, even though it should be protected by at least `AuthorizerToBeSniped`.

If its security context becomes more strict in the target infrastructure, you
should add a DependsOn from it to all the required security resources (here
only to `AuthorizerToBeSniped`).  This dependency will ensure correct ordering
of upgrade operations and makes sure that the authorizer is present before upgrading
`GreetingRequestPOST` to a more sensitive version.

If its security context becomes less strict in the target infrastructure, you
should add a DependsOn from all the required security resources (here
`AuthorizerToBeSniped`) to it.  This dependency ensures correct ordering of
upgrade operations and makes sure that the authorizer is only removed after
upgrading `GreetingRequestPOST` to a less sensitive version.
