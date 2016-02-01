# Revert a security group change lambda function

This Lambda function reverts a security group change. It's based on the work in [this blog post](https://securosis.com/blog/event-driven-security-on-aws-a-practical-example) over at Securosis.

There are three files in this directory:

* This readme.
* The json policy template with the necessary IAM rights.
* The python code for the lambda function

Some notes, which we will update as the code changes over time:

* The main function handler includes a bunch of conditional statements you can use to only trigger reverting a security group change based on things like who requested the change, what security group was changed, if the security group is in a specified VPC, or if the security group has a particular tag. None of those lines will work since they refer to specific identifiers in *my* account, so you *need to change them to work in your account*.
* By default, the function will revert *any security group change in your account*. You need to cut and paste the line "revert_security_group(event)" into a conditional block to only run it based on conditions.
* The function only works for inbound rule changes. It's trivial to modify it to work for egress rule changes, or run it to restrict both ingress and egress. The IAM policy we set will work for both, you just need to change the code.
* This only works for EC2-VPC. EC2-Classic works differently, and my code won't parse an EC2-Classic API call. 
* The code pulls the event details, finds the changes (which could be multiple changes submitted at the same time) and reverses them.
* *There may be ways around this*. I ran through it over the weekend and tested multiple ways of making an EC2-VPC security group change and it always worked, but there might be a way I don't know about that would change the log format enough that my code won't work. Later I plan to update it to work with EC2-Classic, but since I never use that (neither does Securosis) and we advise our clients not to use it, that's low on the priority list. If you find a hole, please drop me a line.
* This works for internal (security group to security group) changes as well as external or internal IP address based rules. 