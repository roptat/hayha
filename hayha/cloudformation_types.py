import sys
import datetime
import collections
from numbers import Number

from .dataflow import Resource, SecurityResource

class CloudFormationResource:
    #  Here are some name changes I thought made things easier to understand.
    #  I've only changed the names here. Let me know what you think, so I can
    #  change the names accross the file (or not).
    #  (edit) I've changed the names to counter-proposal. I don't think there is
    #  a typo in 'connection_to_form' because it's replacing 'managed_connection_flow'??
    #  The way I understand it is that a resource with this property creates/forms connections
    #  between two other resources? Let me know and if everything is okay, I'll just delete these
    #  comments.
    def __init__(self, outgoing_connection=None, incoming_connection=None, connection_to_form=None,
            entrance_protection_of=None, entrance_protection_by=None,
            connection_to_protect=None,
            exit_protection_of=None, exit_protection_by=None,
            contains=None, contained_in=None,
            security=False, accessible=True, container=False):
        """

            I FIGURED I RE-ALIGN EVERYTHING ONCE NEW DOCUMENTATION WAS FULLY COMPLETE.
        PERHAPS WE SHOULD MAKE A "cloudformation_types_documentation.txt" IN CASE
        THIS GETS TOO LONG?

        Background Information:

            CloudFormation resources are implemented into the Hayha tool/files
        using a key-value structure (i.e. For ‘outgoing_connection=[[“K”]]’, the 
        ‘outgoing_connection’ Hayha property is the key and the ‘[[“K”]]’ CloudFormation 
        property/key is the value). 
            CloudFormation files themselves implement resources using a key-value 
        structure as well. In CloudFormation files, a key represents a property 
        of the resource being implemented. For example, 'AWS::ApiGateway::Authorizer' 
        contains the key ‘RestApiId’, which is documented in AWS Documentation as a 
        property of the resource type. In CloudFormation files, a value contains a 
        reference pointer(s) to a resource(s). In this case, the value connected 
        to ‘RestApiId’ would be a String representing the ID of the RestApi resource 
        the authorizer is created in. So, we can conclude for ‘AWS::ApiGateway::Authorizer’, 
        ‘some_protection_of=[[“RestApiId”]]’ exists (turns out to be ‘entrance_protection_of’ 
        after reading AWS Documentation thoroughly). 
            Note, “K” is the name of the CloudFormation property/key. In the Hayha tool/files, 
        “K” acts almost like a placeholder or variable, essentially referring to what 
        the CloudFormation value will be.

        Hayha Property/Key Documentation:

        `outgoing_connection`
            Examples: AWS::ApiGateway::Method',Integration; AWS::EC2::Instance, Volumes
            Description: A key-value property in the parent resource type (“A”) that 
            specifies that “A” can send requests to another resource type (“B”), using 
            “K” which is a CloudFormation property/key name in “A” and refers to/is connected 
            to a value that is a reference pointer to “B”. For example, if Hayha is configured 
            as ‘direct_flow=[[“K”]]’, this would specify a connection from resource type “A” 
            to another resource type (“B”). This relationship can send and receive data both ways, 
            but only resource “A” can initiate communication. This Hayha property is 
            inverse to the reverse_flow property in which, if identically configured, 
            “B” would point to “A”.

        `incoming_connection`
        Examples:
        Description: A key-value property in the parent resource type (“A”) that specifies that “A” receives requests from another resource type (“B”), using “K” which is a CloudFormation property/key name in “A” and refers to/is connected to a value that is a reference pointer to “B”. If configured as ‘reverse_flow=[[“B”]]’, this would specify a connection from resource type “B” to type “A”. This relationship can send and receive data both ways, but only resource type “B” can initiate communication.  The inverse to the direct_flow property in which, if identically configured, “A” would point to “B”.

        ‘connection_to_form’
        Examples:
        Description: A key-value property in the parent resource type (“A”) that specifies that one resource type (“B”) should send a request to another resource type (“C”). If configured as managed_flow=[[“B”, “C”]], the parent resource type ALLOWS (doesn’t really tell “B” to send a request to “C”) “B” to send requests to “C”. Note, this doesn’t necessarily mean “B” will be able to send requests to “C”. If there is a protection/authorization check and “B” has a security level lower than what is necessary to communicate with “C”, communication will fail (same with direct and reverse flow).

        `entrance_protection_of`
        Examples:
        Description: A key-value property in the parent resource(“A”) that specifies that “A” protects all incoming connections to the specified resource (“B”). If any resource (“C”)  has a direct_flow relationship with “B”or if “B” has a reverse_flow with “C” (either “C” is configured with ‘direct_flow = [[“B”]] or “B” is configured with ‘reverse_flow = [[“C”]]’), that connection will be subject to protection/authentication by resource “A”. In these cases, the security level of “A” shall be added onto the current security level of “B”.

        ‘exit_protection_of’
        Examples:
        Description: A key-value property in the parent resource(“A”) that specifies that “A” protects all outgoing connections from the specified resource (“B”).  If “B” has a direct_flow relationship with any other resource (“C”) or if “C” has a reverse_flow with “B” (either “B” is configured with ‘direct_flow = [[“C”]] or “C” is configured with ‘reverse_flow = [[“B”]]’), that connection will be subject to protection/authentication by resource “A”. In these cases, the security level of “A” shall be added onto the current security level of “C”.

        `entrance_protection_by`
        Examples:
        Description:

        ‘exit_protection_by’
        Examples:
        Description:

        `managed_protection_flow`
        Examples:
        Description: A key-value property in the parent resource(“A”) that specifies that “A” protects a specific connection with a specified resource (“B”) and another resource (“C”). “managed_protection_flow”=[[“B”, “C”]] signifies resource “B” has a direct flow connection with resource “C”(or “C” has a reverse flow connection with “B”) and that connection will be subject to protection by resource “A”.

        `accessible`
        Examples:
        Description: This key-value property indicates the parent resource is publicly accessible, which means it has a URL.

        ‘security’
        Examples:
        Description:

        ‘contained_in’
        Examples:
        Description: This key-value property indicates that the parent resource contains other resources. In other words, the other resources are subtypes of the parent resource.

        ‘container’
        Examples:
        Description:  This key-value property indicates that the parent resource is a subtype of the specified resource.

        """
        self.security = security
        self.direct_flow = [] if direct_flow is None else direct_flow
        self.reverse_flow = [] if reverse_flow is None else reverse_flow
        self.managed_flow = [] if managed_flow is None else managed_flow
        self.direct_protection_flow = [] if direct_protection_flow is None else direct_protection_flow
        self.reverse_protection_flow = [] if reverse_protection_flow is None else reverse_protection_flow
        self.managed_protection_flow = [] if managed_protection_flow is None else managed_protection_flow
        self.direct_protected_from_flow = [] if direct_protected_from_flow is None else direct_protected_from_flow
        self.reverse_protected_from_flow = [] if reverse_protected_from_flow is None else reverse_protected_from_flow
        self.contains = [] if contains is None else contains
        self.contained_in = [] if contained_in is None else contained_in
        self.container = container
        self.accessible = accessible

    def is_accessible(self):
        return self.accessible and not self.security

    def is_security(self):
        return self.security

    def is_container(self):
        return self.container

    def get_node(self, name):
        """
        Return a Resource node that corresponds to this resource type.  Name is
        used both as id and as name of the node.
        """
        if self.security:
            return SecurityResource(name, name, original_type=self)
        return Resource(name, name, original_type=self)

    def get_edges(self, content, context):
        """
        Scan the content for references and return a list of edges, according
        to direct_flow, reverse_flow and managed_flow.
        """
        edges = []
        for option in self.direct_flow:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'from': context, 'to': ref})
        for option in self.reverse_flow:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'from': ref, 'to': context})
        for (o1, o2) in self.managed_flow:
            r1 = self.flatten(self.references(content, o1))
            r2 = self.flatten(self.references(content, o2))
            for ref1 in r1:
                for ref2 in r2:
                    edges.append({'from': ref1, 'to': ref2})
        return edges

    def get_security_edges(self, content, context):
        """
        Scan the content for references and return a list of edges according to
        security_flow.  The 'from' node is filtered by the 'security' node, and
        the 'to' node is protected by the 'security' node.
        """
        edges = []
        for option in self.direct_protection_flow:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'security': context, 'to': ref})
        for option in self.reverse_protection_flow:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'security': ref, 'to': context})
        for (o1, o2) in self.managed_protection_flow:
            r1 = self.flatten(self.references(content, o1))
            r2 = self.flatten(self.references(content, o2))
            for ref1 in r1:
                for ref2 in r2:
                    edges.append({'security': ref1, 'to': ref2})
        for option in self.direct_protected_from_flow:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'security': ref, 'from': context})
        for option in self.reverse_protected_from_flow:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'security': context, 'from': ref})
        return edges

    def get_deps(self, content, context):
        """
        Scan the content for dependencies and return as a list.
        """
        return [{'from': context, 'to': x} for x in self.flatten(self.find_deps(content))]

    def get_content(self, content, context):
        """
        Scan the content for containment relations and return as a list.
        """
        edges = []
        for option in self.contains:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'container': context, 'has': ref})
        for option in self.contained_in:
            for ref in self.flatten(self.references(content, option)):
                edges.append({'container': ref, 'has': context})
        return edges

    @staticmethod
    def references(content, option):
        if option == []:
            if isinstance(content, str):
                return [content]
            if isinstance(content, list):
                result = []
                for x in content:
                    result.extend(CloudFormationResource.references(x, option))
                return result
            return CloudFormationResource.find_refs(content)

        if isinstance(content, list):
            return [CloudFormationResource.references(e, option) for e in content]

        key = option[0]
        if isinstance(content, dict) and key in content:
            return CloudFormationResource.references(content[key], option[1:])

        return []

    @staticmethod
    def flatten(x):
        result = []
        for el in x:
            if isinstance(x, collections.Iterable) and not isinstance(el, dict) and not isinstance(el, str):
                result.extend(CloudFormationResource.flatten(el))
            else:
                result.append(el)
        return result

    @staticmethod
    def find_refs(elem):
        """
        scan `elem`, a portion of configuration, for references to other nodes
        and return the list of such references.
        """
        if isinstance(elem, dict):
            refs = []
            for k, v in elem.items():
                if k == 'Ref' or k == '!Ref':
                    assert isinstance(v, str), 'Expected a string: %s' % v
                    refs.append(v)
                elif k == 'Fn::GetAtt':
                    if isinstance(v, str):
                        split = v.split(".")
                        assert len(split) == 2 and split[1] == "Arn", "Expected <reference>.Arn"
                        refs.append(split[0])
                    else:
                        assert isinstance(v, list), 'Expected a list: %s' % v
                        refs.append(v[0])
                else:
                    refs.extend(CloudFormationResource.find_refs(v))
            return refs
        elif isinstance(elem, list):
            return [CloudFormationResource.find_refs(e) for e in elem]
        elif isinstance(elem, str):
            return []
        elif isinstance(elem, bool):
            return []
        elif isinstance(elem, Number):
            return []
        elif isinstance(elem, datetime.date):
            return []
        else:
            raise AssertionError('Unexpected type: %s' % elem)

    @staticmethod
    def find_deps(elem):
        """
        Scan `elem` for dependencies (ordering of updates) on other nodes and
        return such a list.
        """
        if isinstance(elem, dict):
            deps = []
            for k, v in elem.items():
                if k == '!Ref':
                    assert isinstance(v, str), 'Expected a string: %s' % v
                    deps.append(v)
                elif k == "DependsOn":
                    assert isinstance(v, list) or isinstance(v, str), 'Expected a string or an array: %s' % v
                    if isinstance(v, str):
                        v = [v]
                    for dep in v:
                        assert isinstance(dep, str), 'Expected a string: %s' % dep
                        deps.append(dep)
                else:
                    deps.extend(CloudFormationResource.find_deps(v))
            return deps
        elif isinstance(elem, list):
            return [CloudFormationResource.find_deps(e) for e in elem]
        elif isinstance(elem, str):
            return []
        elif isinstance(elem, bool):
            return []
        elif isinstance(elem, Number):
            return []
        elif isinstance(elem, datetime.date):
            return []
        else:
            raise AssertionError('Unexpected type: %s' % elem)


class AbstractNode:
    def __init__(self, id, name, original_type, original_conf, origin):
        self.id = id
        self.name = name
        self.original_type = original_type
        self.original_conf = original_conf
        self.origin = origin

    def get_id(self):
        return self.id

    def get_name(self):
        return self.id

    def get_edges(self, node):
        return self.original_type.get_edges(self.original_conf['Properties'], node)

    def get_deps(self, node):
        return self.original_type.get_deps(self.original_conf, node)

    def get_security_edges(self, node):
        return self.original_type.get_security_edges(self.original_conf['Properties'], node)

    def get_content(self, node):
        return self.original_type.get_content(self.original_conf['Properties'], node)

    def get_node(self):
        n = self.original_type.get_node(self.name)
        n.set_original_type(self)
        n.set_origin(self.origin)
        return n

    def is_accessible(self):
        return self.original_type.is_accessible()

    def is_container(self):
        return self.original_type.is_container()


## Type declarations

KNOWN_TYPES = {
  'AWS::ApiGateway::Authorizer':
    CloudFormationResource(security=True,
        direct_protection_flow=[["RestApiId"]]),
  'AWS::ApiGateway::Method':
    CloudFormationResource(
        reverse_protection_flow=[["AuthorizerId"]],
        direct_flow=[["Integration"]],
        contained_in=[["RestApiId"]]),
  'AWS::ApiGateway::RestApi':
    CloudFormationResource(container=True),

#  My thought process in making these tables containers is that they contain data.
#  I'm pretty sure they contain resources based off what it describes in the CloudFormation properties.
#  To be more specific, some of the properties are of resource type and described as "on the table".
#  I'm debating whether you could send requests to a whole table or not, but am leaning towards you can't.
  'AWS::DynamoDB::GlobalTable':
    CloudFormationResource(container=True),
  'AWS::DynamoDB::Table':
    CloudFormationResource(container=True),
    
  'AWS::EC2::Host': 
    CloudFormationResource(container=True),
  'AWS::EC2::Instance':
    CloudFormationResource(contained_in=[["HostId"], ["HostResourceGroupArn"], ["SubnetId"]],
        reverse_protection_flow=[["IamInstanceProfile"], ["SecurityGroupIds"], ["SecurityGroups"]],
        direct_flow=[["Volumes"]]),
  'AWS::EC2::InternetGateway':
    CloudFormationResource(),
  'AWS::EC2::NetworkAcl':
    CloudFormationResource(security=True,
        direct_protection_flow=[["VpcId"]]),
  'AWS::EC2::NetworkAclEntry':
    CloudFormationResource(security=True,
        direct_protection_flow=[["NetworkAclId"]]),
  'AWS::EC2::SecurityGroup':
    CloudFormationResource(security=True,
      direct_protection_flow=[["SecurityGroupEgress"]],
      reverse_protected_from_flow=[["SecurityGroupIngress"]]),
  'AWS::EC2::SecurityGroupEgress':
    CloudFormationResource(security=True),
  'AWS::EC2::SecurityGroupIngress':
    CloudFormationResource(security=True),
  'AWS::EC2::Subnet':
    CloudFormationResource(container=True, accessible=False,
        contained_in=[["VpcId"]]),
  'AWS::EC2::SubnetNetworkAclAssociation':
    CloudFormationResource(
        accessible=False,
        managed_protection_flow=[(["NetworkAclId"], ["SubnetId"])]),
  'AWS::EC2::Volume':
    CloudFormationResource(accessible=False),
  'AWS::EC2::VPC':
    CloudFormationResource(accessible=False, container=True),
  'AWS::EC2::VPCGatewayAttachment':
    CloudFormationResource(accessible=False,
        managed_flow=[(["InternetGatewayId"], ["VpcId"]),
            (["VpnGatewayId"], ["VpcId"])]),

  'AWS::ECS::MountGroup':
    CloudFormationResource(),
  'AWS::ECS::Cluster':
    CloudFormationResource(),

  'AWS::EFS::MountGroup':
    CloudFormationResource(),
  'AWS::EFS::MountTarget':
    CloudFormationResource(),
  'AWS::EFS::FileSystem':
    CloudFormationResource(),

  'AWS::Glue::Classifier':
    CloudFormationResource(),
#  I'm unsure if there should be a direct_flow to CatalogID because wouldn't
#  we need to send a request to the data catalog to create the catalog object (which I am assuming is this Connection)
  'AWS::Glue::Connection':
    CloudFormationResource(),
#  This specific resource will be important to reference when creating the new Hayha property
#  that accounts for increasing a resource's security authorization. "Role" is CloudFormation property
#  that will be linked to this new Hayha property 
# 'AWS::Glue::Crawler':
#   CloudFormationResource(reverse_protection_flow=[["CrawlerSecurityConfiguration"]],
#       direct_flow=[["DatabaseName"], ["Targets"]]),  
#  Again, also unsure whether there should be a direct_flow to CatalogID.  
  'AWS::Glue::Database':
    CloudFormationResource(container=True),
#  Unsure if there should be a direct_protection_flow to CatalogID.    
  'AWS::Glue::DataCatalogEncryptionSettings':
    CloudFormationResource(security=True),

  'AWS::IAM::InstanceProfile':
    CloudFormationResource(container=True,
        security=True,
        contains=[["Roles"]]),
  'AWS::IAM::Policy':
    CloudFormationResource(security=True,
        reverse_protection_flow=[["Roles"]]),
  'AWS::IAM::Role':
    CloudFormationResource(security=True,
        reverse_protection_flow=[["ManagedPolicyArns"], ["PermissionsBoundary"],
                                 ["Policies"]],
        accessible=False),

  'AWS::Lambda::Function':
    CloudFormationResource(reverse_protection_flow=[["Role"]], accessible=False),
  'AWS::Lambda::Permission':
    CloudFormationResource(security=True,
        direct_protection_flow=[["FunctionName"]],
        reverse_protected_from_flow=[["SourceArn"]],
        accessible=False),
 
  'AWS::RDS::DBInstance':
    CloudFormationResource(reverse_protection_flow=[["AccessControl"]]),
  'AWS::RDS::DBCluster':
    CloudFormationResource(reverse_protection_flow=[["AccessControl"]]),
  'AWS::RDS::DBSubnetGroup':
    CloudFormationResource(reverse_protection_flow=[["AccessControl"]]),

  'AWS::S3::Bucket':
    CloudFormationResource(reverse_protection_flow=[["AccessControl"]]),
  'AWS::S3::BucketPolicy':
    CloudFormationResource(security=True,
        direct_protection_flow=[["Bucket"]]),

}

IGNORED_TYPES = [

  'Custom::MaxThroughputCalculator',

  'AWS::ApiGateway::Account',
  'AWS::ApiGateway::Deployment',
  'AWS::ApiGateway::Resource',
  'AWS::ApiGateway::Stage',

  'AWS::AutoScaling::AutoScalingGroup',
  'AWS::AutoScaling::LaunchConfiguration',
  'AWS::AutoScaling::ScalingPolicy',
  'AWS::AutoScaling::LifecycleHook',

  'AWS::ApplicationAutoScaling::LifecycleHook',

  'AWS::Backup::BackupSelection',
  'AWS::Backup::BackupPlan',
  'AWS::Backup::BackupVault',

  'AWS::CloudWatch::Alarm',

  'AWS::CloudFront::Distribution',

  'AWS::DirectoryService::SimpleAD',

  'AWS::EC2::EIP',
  'AWS::EC2::EIPAssociation',
  'AWS::EC2::NatGateway',
  'AWS::EC2::NetworkInterface',
  'AWS::EC2::PlacementGroup',
  'AWS::EC2::Route',
  'AWS::EC2::RouteTable',
  'AWS::EC2::SubnetRouteTableAssociation',

  'AWS::ElasticLoadBalancingV2::Listener',
  'AWS::ElasticLoadBalancingV2::TargetGroup',
  'AWS::ElasticLoadBalancingV2::LoadBalancer',

  'AWS::Events::Rule',


  
  'AWS::Logs::LogGroup',

  'AWS::Route53::RecordSet',

  'AWS::SSM::Association',
  'AWS::SSM::Document',
  'AWS::SSM::MaintenanceWindow',
  'AWS::SSM::MaintenanceWindowTarget',
  'AWS::SSM::MaintenanceWindowTask',

  'AWS::SQS::Queue',

  'AWS::SNS::Subscription',
  'AWS::SNS::Topic'

]
