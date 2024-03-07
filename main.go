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
	if err := csvWriter.Write([]string{"type", "hostname", "security_group_id", "sg_type", "description", "from_port", "to_port", "protocol", "cidr_block"}); err != nil {
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
			hostname := inst.NetworkInterfaces[0].PrivateDnsName
			// Iterate over the security groups
			for _, sg := range inst.SecurityGroups {
				groupId := *sg.GroupId

				// Write the security group to the CSV
				if err := csvWriter.Write([]string{"sg", *hostname, groupId}); err != nil {
					logger.Error(err.Error())
				}

				// Describe the security group to get the rules
				sgs, err := svc.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{groupId},
				})
				if err != nil {
					logger.Error(err.Error())
				}

				// Iterate over the security group rules
				for _, sg := range sgs.SecurityGroups {
					// Iterate over the ingress rules
					for _, ipPerm := range sg.IpPermissions {
						var fromPortStr, toPortStr string

						// If the FromPort is nil, set it to 0
						// If the ToPort is nil, set it to 0
						if ipPerm.FromPort == nil {
							fromPortStr = "0"
						} else {
							// Convert the FromPort to a string
						  fromPortStr = strconv.Itoa(int(*ipPerm.FromPort))
						}
						if ipPerm.ToPort == nil {
							toPortStr = "0"
						} else {
							// Convert the ToPort to a string
							toPortStr = strconv.Itoa(int(*ipPerm.ToPort))
						}

						// Iterate over the CIDR ranges
						for _, ipRange := range ipPerm.IpRanges {
							// Write the security group rule to the CSV
							if err := csvWriter.Write([]string{"sgrule", *hostname, groupId, "ingress", *sg.Description, fromPortStr, toPortStr, *ipPerm.IpProtocol, *ipRange.CidrIp}); err != nil {
								logger.Error(err.Error())
							}
						}
					}

					// Iterate over the egress rules
					for _, ipPermEgress := range sg.IpPermissionsEgress {
						var fromPortStr, toPortStr string

						// If the FromPort is nil, set it to 0
						// If the ToPort is nil, set it to 0
						if ipPermEgress.FromPort == nil {
							fromPortStr = "0"
						} else {
							// Convert the FromPort to a string
							fromPortStr = strconv.Itoa(int(*ipPermEgress.FromPort))
						}
						if ipPermEgress.ToPort == nil {
							toPortStr = "0"
						} else {
							// Convert the ToPort to a string
							toPortStr = strconv.Itoa(int(*ipPermEgress.ToPort))
						}
				  
						// Iterate over the CIDR ranges
				    for _, ipRange := range ipPermEgress.IpRanges {
							// Write the security group rule to the CSV
					    if err := csvWriter.Write([]string{"sgrule", *hostname, groupId, "egress", *sg.Description, fromPortStr, toPortStr, *ipPermEgress.IpProtocol, *ipRange.CidrIp}); err != nil {
					      logger.Error(err.Error())
					    }
					  }
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
