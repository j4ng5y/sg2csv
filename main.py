#!/usr/bin/env python3

import csv
import argparse
import boto3
from botocore.exceptions import ClientError


def cli():
    """CLI argument parser.

    Keyword arguments:
    None
    """

    # Set up the argument parser
    parser = argparse.ArgumentParser(
        description="Export Security Groups and Security Group Rules to a CSV"
    )

    # Add the arguments to the parser
    parser.add_argument(
        "--region", default="us-east-1", help="AWS region (default: us-east-1)"
    )
    parser.add_argument("--profile", default="", help="AWS Profile (default: None)")
    parser.add_argument(
        "--output", default="sg.csv", help="Output file (default: sg.csv)"
    )

    # Parse the arguments and return them
    return parser.parse_args()


def main(args):
    """Main function to export Security Groups and Security Group Rules to a CSV.

    Keyword arguments:
    args -- CLI arguments
    """

    # Set up the AWS session
    # If a profile is provided, use it
    # If a region is provided, use it
    # If both a profile and region are provided, use them
    # If neither a profile nor region are provided, use the default session
    if args.profile and args.region:
        aws = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    elif args.region:
        aws = boto3.session.Session(region_name=args.region)
    elif args.profile:
        aws = boto3.session.Session(profile_name=args.profile)
    else:
        aws = boto3.session.Session()

    # Set up the EC2 resource
    ec2 = aws.resource("ec2")

    # Open the output file and write the headers initially
    with open(args.output, "w", newline="") as f:
        csv_writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(
            [
                "Type",
                "Instance ID",
                "Security Group ID",
                "Security Group Description",
                "Security Group Rule Type",
                "IP Protocol",
                "From Port",
                "To Port",
                "CIDR Range",
            ]
        )

        # Iterate over the instances and security groups and handle any errors
        try:
            # Iterate over the instances
            for instance in ec2.instances.all():
                # Iterate over the security groups
                for sg in ec2.security_groups.all():
                    # Iterate over the security group ingress rules
                    for ip_permission in sg.ip_permissions:
                        # Iterate over the CIDR ranges
                        for ip_range in ip_permission["IpRanges"]:
                            # Try to get the from and to ports, if they exist
                            # If they don't exist, set them to 0
                            try:
                                fromPort = ip_permission["FromPort"]
                            except KeyError:
                                fromPort = 0
                            try:
                                toPort = ip_permission["ToPort"]
                            except KeyError:
                                toPort = 0

                            # Write the row to the CSV
                            csv_writer.writerow(
                                [
                                    "sgr",
                                    f"{instance.private_dns_name}",
                                    f"{sg.group_id}",
                                    f"{sg.description}",
                                    "ingress",
                                    f"{ip_permission['IpProtocol']}",
                                    f"{fromPort}",
                                    f"{toPort}",
                                    f"{ip_range['CidrIp']}",
                                ]
                            )
                    # Iterate over the security group egress rules
                    for ip_permission_egress in sg.ip_permissions_egress:
                        # Iterate over the CIDR ranges
                        for ip_range in ip_permission_egress["IpRanges"]:
                            # Try to get the from and to ports, if they exist
                            # If they don't exist, set them to 0
                            try:
                                fromPort = ip_permission_egress["FromPort"]
                            except KeyError:
                                fromPort = 0
                            try:
                                toPort = ip_permission_egress["ToPort"]
                            except KeyError:
                                toPort = 0

                            # Write the row to the CSV
                            csv_writer.writerow(
                                [
                                    "sgr",
                                    f"{instance.private_dns_name}",
                                    f"{sg.group_id}",
                                    f"{sg.description}",
                                    "egress",
                                    f"{ip_permission_egress['IpProtocol']}",
                                    f"{fromPort}",
                                    f"{toPort}",
                                    f"{ip_range['CidrIp']}",
                                ]
                            )

                    # Write the security group to the CSV
                    csv_writer.writerow(
                        [
                            "sg",
                            f"{instance.private_dns_name}",
                            f"{sg.group_id}",
                            f"{sg.description}",
                        ]
                    )
        # Handle any errors
        except ClientError as e:
            print(e)


# Run the main function if the script is executed
if __name__ == "__main__":
    main(args=cli())
