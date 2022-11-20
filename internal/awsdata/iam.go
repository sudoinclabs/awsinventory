package awsdata

import (
	"fmt"
	"net/url"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/sudoinclabs/awsinventory/internal/inventory"
	"github.com/sirupsen/logrus"
)

const (
	// AssetTypeIAMUser is the value used in the AssetType field when fetching IAM users
	AssetTypeIAMUser string = "IAM User"
	AssetTypeIAMRole string = "IAM Role"
	AssetTypeIAMPolicy string = "IAM Policy"

	// ServiceIAM is the key for the IAM service
	ServiceIAM string = "iam"
	PolicySope string = "Local"
)

func (d *AWSData) loadIAMUsers() {
	defer d.wg.Done()

	iamSvc := d.clients.GetIAMClient(DefaultRegion)

	log := d.log.WithFields(logrus.Fields{
		"region":  "global",
		"service": ServiceIAM,
	})

	log.Info("loading data")

	var users []*iam.User
	done := false
	params := &iam.ListUsersInput{}
	for !done {
		out, err := iamSvc.ListUsers(params)

		if err != nil {
			log.Errorf("failed to list users: %s", err)
			return
		}

		users = append(users, out.Users...)

		if aws.BoolValue(out.IsTruncated) {
			params.Marker = out.Marker
		} else {
			done = true
		}
	}

	log.Info("processing data iam users")

	for _, u := range users {
		d.rows <- inventory.Row{
			UniqueAssetIdentifier: aws.StringValue(u.UserName),
			Virtual:               true,
			AssetType:             AssetTypeIAMUser,
			SerialAssetTagNumber:  aws.StringValue(u.Arn),
		}
	}

	log.Info("finished processing data")


	var roles []*iam.Role
	roledone := false
	roleparams := &iam.ListRolesInput{}
	for !roledone {
		out, err := iamSvc.ListRoles(roleparams)

		if err != nil {
			log.Errorf("failed to list roles: %s", err)
			return
		}

		roles = append(roles, out.Roles...)

		if aws.BoolValue(out.IsTruncated) {
			roleparams.Marker = out.Marker
		} else {
			roledone = true
		}
	}

	log.Info("processing data iam role")

	for _, u := range roles {
		decodedValue, err := url.QueryUnescape(aws.StringValue(u.AssumeRolePolicyDocument))
		if err != nil {
			log.Fatal(err)
		}
		d.rows <- inventory.Row{
			UniqueAssetIdentifier: aws.StringValue(u.RoleName),
			Virtual:               true,
			AssetType:             AssetTypeIAMRole,
			NetBIOSName:                    aws.StringValue(u.RoleName),
			Comments:                       decodedValue,
			SerialAssetTagNumber:  aws.StringValue(u.Arn),
		}
	}

	log.Info("finished processing data")

	var policies []*iam.Policy
	policiesdone := false
	polparams := &iam.ListPoliciesInput{Scope: aws.String("Local"),}
	for !policiesdone {
		out, err := iamSvc.ListPolicies(polparams)

		if err != nil {
			log.Errorf("failed to list policies: %s", err)
			return
		}

		policies = append(policies, out.Policies...)

		if aws.BoolValue(out.IsTruncated) {
			polparams.Marker = out.Marker
		} else {
			policiesdone = true
		}
	}

	log.Info("processing data iam role")

	for _, u := range policies {
		d.rows <- inventory.Row{
			UniqueAssetIdentifier: aws.StringValue(u.PolicyName),
			Virtual:               true,
			AssetType:             AssetTypeIAMPolicy,
			NetBIOSName:                    aws.StringValue(u.PolicyName),
			Comments:                       fmt.Sprintf("AttachmentCount: %d,\nCreate Date: %s,\n UpdateDate: %s,\n IsAttachable: %t", aws.Int64Value(u.AttachmentCount),aws.TimeValue(u.CreateDate),aws.TimeValue(u.UpdateDate),aws.BoolValue(u.IsAttachable)),
			SerialAssetTagNumber:  aws.StringValue(u.Arn),
			BaselineConfigurationName: aws.StringValue(u.PolicyId),
			OSNameAndVersion:          aws.StringValue(u.DefaultVersionId),
		}
	}

	log.Info("finished processing data")
}
