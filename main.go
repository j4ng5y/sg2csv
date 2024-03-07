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

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

var (
	awsProfile string
	outputFile string
)

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

	outFile, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error(err.Error())
	}

	csvWriter := csv.NewWriter(outFile)
	if err := csvWriter.Write([]string{"type", "hostname", "security_group_id", "sg_type", "description", "from_port", "to_port", "protocol", "cidr_block"}); err != nil {
		logger.Error(err.Error())
	}

	if awsProfile != "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(awsProfile))
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO())
	}

	if err != nil {
		logger.Error(err.Error())
	}

	svc := ec2.NewFromConfig(cfg)

	insts, err := svc.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	if err != nil {
		logger.Error(err.Error())
	}

	for _, res := range insts.Reservations {
		for _, inst := range res.Instances {
			hostname := inst.NetworkInterfaces[0].PrivateDnsName
			for _, sg := range inst.SecurityGroups {
				groupId := *sg.GroupId

				if err := csvWriter.Write([]string{"sg", *hostname, groupId}); err != nil {
					logger.Error(err.Error())
				}

				sgs, err := svc.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{groupId},
				})
				if err != nil {
					logger.Error(err.Error())
				}

				for _, sg := range sgs.SecurityGroups {
					for _, ipPerm := range sg.IpPermissions {
						var fromPortStr, toPortStr string
						if ipPerm.FromPort == nil {
							fromPortStr = "0"
						} else {
						  fromPortStr = strconv.Itoa(int(*ipPerm.FromPort))
						}
						if ipPerm.ToPort == nil {
							toPortStr = "0"
						} else {
							toPortStr = strconv.Itoa(int(*ipPerm.ToPort))
						}

						for _, ipRange := range ipPerm.IpRanges {
							if err := csvWriter.Write([]string{"sgrule", *hostname, groupId, "ingress", *sg.Description, fromPortStr, toPortStr, *ipPerm.IpProtocol, *ipRange.CidrIp}); err != nil {
								logger.Error(err.Error())
							}
						}
					}
					for _, ipPermEgress := range sg.IpPermissionsEgress {
						var fromPortStr, toPortStr string
						if ipPermEgress.FromPort == nil {
							fromPortStr = "0"
						} else {
							fromPortStr = strconv.Itoa(int(*ipPermEgress.FromPort))
						}
						if ipPermEgress.ToPort == nil {
							toPortStr = "0"
						} else {
							toPortStr = strconv.Itoa(int(*ipPermEgress.ToPort))
						}
				  
				    for _, ipRange := range ipPermEgress.IpRanges {
					    if err := csvWriter.Write([]string{"sgrule", *hostname, groupId, "egress", *sg.Description, fromPortStr, toPortStr, *ipPermEgress.IpProtocol, *ipRange.CidrIp}); err != nil {
					      logger.Error(err.Error())
					    }
					  }
					}
				}
			}
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		logger.Error(err.Error())
	}
}
