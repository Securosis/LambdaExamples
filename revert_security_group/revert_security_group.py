from __future__ import print_function

# A demonstration AWS Lmbda function to revert a security group change based on a CloudWatch event.
# By Rich Mogull and Securosis, released under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International license.
# http://creativecommons.org/licenses/by-nc-sa/4.0/ ******** https://securosis.com

# This lambda function will reverse any security group changes when triggered by a CloudWatch event
# that shows an ingress change. It *does not* work for outbound changes, but as you can see
# if you review the code it could easily be modified for that.
# The demonstration code also includes various conditional options. If you don't use one of these 
# this will apply to every change in your account. To use them, modify the parameters and then
# move the function call into the conditional block.

import json
import urllib
import boto3

print('Loading function')

ec2 = boto3.client('ec2')


def lambda_handler(event, context):
    # dump the raw event for log purposes
    print("An unauthorized security group change was detected and will be remediated. The event details are:")
    print("----------------------")
    print("Received event: " + json.dumps(event, indent=5))
    print("----------------------")
    
    # Only execute if the change was in a certain region
    if event["detail"]["awsRegion"] == "us-west-2":
        print("Region is us-west-2")
    
    # Only execute if the change *was not* from a designated admin account
    if event["detail"]["userIdentity"]["arn"] != "arn:aws:iam::your account number here:test":
        print("Someone other than the test account tried to make the change")
    
    # Only execute if the change was made on a specific security group
    if event["detail"]["requestParameters"]["groupId"] == "sg-0ac49e6f":
        print("The designate security group was changed")
        
    # Only execute if the change was made on a specific security group
    if event["detail"]["requestParameters"]["groupId"] == "sg-60adbf02":
        print("The designate security group was changed")
        
    # Only execute if the security group is in a designated VPC
    secgroup = event["detail"]["requestParameters"]["groupId"]
    sec_details = ec2.describe_security_groups(GroupIds=[secgroup])
    vpc = sec_details["SecurityGroups"][0]["VpcId"]
    if vpc == "vpc-fbc4a793":
        print("The security group was in the designated vpc")
    
    # Only execute if the security group has a particular tag
    secgroup = event["detail"]["requestParameters"]["groupId"]
    sec_details = ec2.describe_security_groups(GroupIds=[secgroup])
    tags = sec_details["SecurityGroups"][0]["Tags"]
    for tag in tags:
        if (tag["Key"] == "SecurityLevel") and (tag["Value"] == "High"):
            print("The security group is tagged with a security level of high")
        
    revert_security_group(event)
    
def revert_security_group(event):
        # Determine if this was a single security group change (EC2-Classic)
    # or a group of changes. Then reverse the change accordingly.
    # Right now we only use the EC2-VPC version. The event data for EC2-VPC
    # always seems to trigger appropriately, but we have the placeholder to
    # either add support for EC2-Classic or if we determine there is another
    # way to trigger that format of the event.
    
    if "ipPermissions" in event["detail"]["requestParameters"]:
        group = event["detail"]["requestParameters"]["groupId"]
        permissions = []
        # iterate through the IP permissions and clean it up so we can make our API call to revoke the group
        for item in event["detail"]["requestParameters"]["ipPermissions"]["items"]:
            global permissions
            # these next bits of code just clean things up so we can make the API call.
            # the event formatting is different than what we need to insert, sometimes just changing the case of a variable.
            protocol=str(item["ipProtocol"])
            # Determine if it was a group to group request or an IP range request
            if item["ipRanges"] != {}:
                IpRanges=[]
                for ipranges in item["ipRanges"]["items"]:
                    global IpRanges
                    IpRanges.append({"CidrIp": ipranges["cidrIp"]})
                permissions.append({"IpProtocol": protocol, "ToPort": item["toPort"], "FromPort": item["fromPort"], "IpRanges": IpRanges})
            elif item["groups"] !={}:
                GroupId=[]
                for groups in item["groups"]["items"]:
                    global GroupId
                    GroupId.append({"GroupId": groups["groupId"]})
                permissions.append({"IpProtocol": protocol, "ToPort": item["toPort"], "FromPort": item["fromPort"], "UserIdGroupPairs": GroupId})
            print(permissions)
        remove_rule = ec2.revoke_security_group_ingress(
        GroupId=group,
        IpPermissions=permissions
        )
    else:
        print("An ingress rule change was detected, but not in the expected format. You should debug and find out why. Probably an EC2-Classic call.")