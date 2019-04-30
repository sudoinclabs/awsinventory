package awsdata_test

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elb/elbiface"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	. "github.com/manywho/awsinventory/internal/awsdata"
	"github.com/manywho/awsinventory/internal/inventory"
)

var testELBRows = []inventory.Row{
	{
		UniqueAssetIdentifier: "abcdefgh12345678",
		Virtual:               true,
		DNSNameOrURL:          "abcdefgh12345678.ValidRegions[0].elb.amazonaws.com",
		Location:              ValidRegions[0],
		AssetType:             AssetTypeELB,
		Function:              "mydomain.com",
		VLANNetworkID:         "vpc-abcdefgh",
	},
	{
		UniqueAssetIdentifier: "12345678abcdefgh",
		Virtual:               true,
		DNSNameOrURL:          "12345678abcdefgh.ValidRegions[0].elb.amazonaws.com",
		Location:              ValidRegions[0],
		AssetType:             AssetTypeELB,
		Function:              "another.com",
		VLANNetworkID:         "vpc-12345678",
	},
	{
		UniqueAssetIdentifier: "a1b2c3d4e5f6g7h8",
		Virtual:               true,
		DNSNameOrURL:          "a1b2c3d4e5f6g7h8.ValidRegions[0].elb.amazonaws.com",
		Location:              ValidRegions[0],
		AssetType:             AssetTypeELB,
		Function:              "yetanother.com",
		VLANNetworkID:         "vpc-a1b2c3d4",
	},
}

// Test Data
var testELBOutput = &elb.DescribeLoadBalancersOutput{
	LoadBalancerDescriptions: []*elb.LoadBalancerDescription{
		{
			LoadBalancerName:        aws.String(testELBRows[0].UniqueAssetIdentifier),
			CanonicalHostedZoneName: aws.String(testELBRows[0].Function),
			DNSName:                 aws.String(testELBRows[0].DNSNameOrURL),
			VPCId:                   aws.String(testELBRows[0].VLANNetworkID),
		},
		{
			LoadBalancerName:        aws.String(testELBRows[1].UniqueAssetIdentifier),
			CanonicalHostedZoneName: aws.String(testELBRows[1].Function),
			DNSName:                 aws.String(testELBRows[1].DNSNameOrURL),
			VPCId:                   aws.String(testELBRows[1].VLANNetworkID),
		},
		{
			LoadBalancerName:        aws.String(testELBRows[2].UniqueAssetIdentifier),
			CanonicalHostedZoneName: aws.String(testELBRows[2].Function),
			DNSName:                 aws.String(testELBRows[2].DNSNameOrURL),
			VPCId:                   aws.String(testELBRows[2].VLANNetworkID),
		},
	},
}

// Mocks
type ELBMock struct {
	elbiface.ELBAPI
}

func (e ELBMock) DescribeLoadBalancers(cfg *elb.DescribeLoadBalancersInput) (*elb.DescribeLoadBalancersOutput, error) {
	return testELBOutput, nil
}

type ELBErrorMock struct {
	elbiface.ELBAPI
}

func (e ELBErrorMock) DescribeLoadBalancers(cfg *elb.DescribeLoadBalancersInput) (*elb.DescribeLoadBalancersOutput, error) {
	return &elb.DescribeLoadBalancersOutput{}, testError
}

// Tests
func TestCanLoadELBs(t *testing.T) {
	d := New(logrus.New(), TestClients{ELB: ELBMock{}})

	d.Load([]string{ValidRegions[0]}, []string{ServiceELB})

	var count int
	d.MapRows(func(row inventory.Row) error {
		require.Equal(t, testELBRows[count], row)
		count++
		return nil
	})
	require.Equal(t, 3, count)
}

func TestLoadELBsLogsError(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()

	d := New(logger, TestClients{ELB: ELBErrorMock{}})

	d.Load([]string{ValidRegions[0]}, []string{ServiceELB})

	require.Contains(t, hook.LastEntry().Message, testError.Error())
}