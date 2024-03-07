#!/usr/bin/env python3

import csv
import argparse
import boto3
from botocore.exceptions import ClientError


def cli():
    parser = argparse.ArgumentParser(
        description="Export Security Groups and Security Group Rules to a CSV"
    )
    parser.add_argument(
        "--region", default="us-east-1", help="AWS region (default: us-east-1)"
    )
    parser.add_argument("--profile", default="", help="AWS Profile (default: None)")
    parser.add_argument(
        "--output", default="sg.csv", help="Output file (default: sg.csv)"
    )
    return parser.parse_args()


def main(args):
    if args.profile and args.region:
        aws = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    elif args.region:
        aws = boto3.session.Session(region_name=args.region)
    elif args.profile:
        aws = boto3.session.Session(profile_name=args.profile)
    else:
        aws = boto3.session.Session()

    ec2 = aws.resource("ec2")

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
        try:
            for instance in ec2.instances.all():
                for sg in ec2.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        for ip_range in ip_permission["IpRanges"]:
                            try:
                                fromPort = ip_permission["FromPort"]
                            except KeyError:
                                fromPort = 0
                            try:
                                toPort = ip_permission["ToPort"]
                            except KeyError:
                                toPort = 0
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
                    for ip_permission_egress in sg.ip_permissions_egress:
                        for ip_range in ip_permission_egress["IpRanges"]:
                            try:
                                fromPort = ip_permission_egress["FromPort"]
                            except KeyError:
                                fromPort = 0
                            try:
                                toPort = ip_permission_egress["ToPort"]
                            except KeyError:
                                toPort = 0
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
                    csv_writer.writerow(
                        [
                            "sg",
                            f"{instance.private_dns_name}",
                            f"{sg.group_id}",
                            f"{sg.description}",
                        ]
                    )
        except ClientError as e:
            print(e)


if __name__ == "__main__":
    main(args=cli())
