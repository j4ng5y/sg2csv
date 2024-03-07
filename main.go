package main

import (
	"context"
	"encoding/csv"
	"flag"
	"log/slog"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Set up the logger
var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

// Set up the flag variables
var (
	awsProfile string
	outputFile string
)

// Parse the CLI flags
func init() {
	flag.StringVar(&awsProfile, "profile", "", "The AWS Profile to use")
	flag.StringVar(&outputFile, "output", "out.csv", "The output file to write to")
	flag.Parse()
}

func main() {
	var (
		cfg aws.Config
		err error
	)

	// Open the output file
	outFile, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error(err.Error())
	}

	// Create the CSV writer with the output file
	csvWriter := csv.NewWriter(outFile)
	if err := csvWriter.Write([]string{"type", "hostname", "security_group_id", "security_group_rule_id", "sgr_type", "description", "from_port", "to_port", "protocol", "cidr_block_or_reference_sg_id"}); err != nil {
		logger.Error(err.Error())
	}

	// Load the AWS config
	if awsProfile != "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(awsProfile))
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO())
	}

	if err != nil {
		logger.Error(err.Error())
	}

	// Create the EC2 client
	svc := ec2.NewFromConfig(cfg)

	// Describe the instances
	insts, err := svc.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	if err != nil {
		logger.Error(err.Error())
	}

	// Iterate over the instances which are nested in reservations
	for _, res := range insts.Reservations {
		for _, inst := range res.Instances {
			// Iterate over the security groups
			for _, sg := range inst.SecurityGroups {
				// Write the security group to the CSV
				if err := csvWriter.Write([]string{"sg", *inst.NetworkInterfaces[0].PrivateDnsName, *sg.GroupId}); err != nil {
					logger.Error(err.Error())
				}

				// Get the security group rules
		    sgrs, err := svc.DescribeSecurityGroupRules(context.TODO(), &ec2.DescribeSecurityGroupRulesInput{
				  Filters: []ec2Types.Filter{
					  {
						  Name:  aws.String("group-id"),
							Values: []string{*sg.GroupId},
						},
					},
				},)
				if err != nil {
					logger.Error(err.Error())
				}

				// Iterate over the security group rules
				for _, sgr := range sgrs.SecurityGroupRules {
					var sgrDesc, sgrProtocol, sgrType, sgrFromPort, sgrToPort, sgrCidr string
				
					// Build a local variable for the sgr Description and default to "Unspecified" if it's nil
					if sgr.Description == nil {
						sgrDesc = "Unspecified"
					} else {
						sgrDesc = *sgr.Description
					}

					// Determine the type of security group rule
					if *sgr.IsEgress {
						sgrType = "egress"
					} else {
						sgrType = "ingress"
					}

					// Build a local variable for the sgr FromPort and ToPort and default to "0" if it's nil
					if sgr.FromPort == nil {
						sgrFromPort = "0"
					} else {
						sgrFromPort = strconv.Itoa(int(*sgr.FromPort))
					}
					
					// Build a local variable for the sgr ToPort and default to "0" if it's nil
					if sgr.ToPort == nil {
						sgrToPort = "0"
					} else {
						sgrToPort = strconv.Itoa(int(*sgr.ToPort))
					}

					// Build a local variable for the sgr Protocol and default to "-1" if it's nil
					if sgr.IpProtocol == nil {
						sgrProtocol = "-1"
					} else {
						sgrProtocol = *sgr.IpProtocol
					}

					// Build a local variable for the sgr Cidr and default to "Unspecified" if the IPv4 and IPv6 CIDRs are nil
					// and there is not referenced group. If there is a referenced group, use the GroupId, otherwise use the
					// IPv4 or IPv6 CIDR
					if sgr.CidrIpv4 == nil {
						if sgr.CidrIpv6 == nil {
							if sgr.ReferencedGroupInfo == nil {
								sgrCidr = "Unspecified"
							} else {
								sgrCidr = *sgr.ReferencedGroupInfo.GroupId
							}
						} else {
							sgrCidr = *sgr.CidrIpv6
						}
					} else {
						sgrCidr = *sgr.CidrIpv4
					}

					// Write the security group rule to the CSV
					if err := csvWriter.Write([]string{"sgr", *inst.NetworkInterfaces[0].PrivateDnsName, *sg.GroupId, *sgr.SecurityGroupRuleId, sgrType, sgrDesc, sgrFromPort, sgrToPort, sgrProtocol, sgrCidr}); err != nil {
						logger.Error(err.Error())
					}
				}
			}
		}
	}

	// Flush the CSV writer so we don't leave any data behind
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		logger.Error(err.Error())
	}
}
