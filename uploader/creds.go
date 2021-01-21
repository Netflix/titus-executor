package uploader

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/request"
	securejoin "github.com/cyphar/filepath-securejoin"
)

// Emulates the EC2RoleCreds Provider but using a custom path
// https://github.com/aws/aws-sdk-go/blob/master/aws/credentials/ec2rolecreds/ec2_role_provider.go

const ProviderName = "IMDSRoleProvider"

// IMDSRoleProvider will attempt to load credentials from the imds proxy in a special path
type IMDSRoleProvider struct {
	credentials.Expiry

	Client *ec2metadata.EC2Metadata

	ExpiryWindow time.Duration
}

func NewIMDSCredentials(c client.ConfigProvider) *credentials.Credentials {
	p := &IMDSRoleProvider{
		Client: ec2metadata.New(c),
	}

	return credentials.NewCredentials(p)
}

const credentialPath = "iam/logging/security-credentials/"

// Retrieve retrieves credentials from the Instance Metadata Service.
// Error will be returned if the request fails, or unable to extract the desired credentials.
func (i *IMDSRoleProvider) Retrieve() (credentials.Value, error) {
	return i.RetrieveWithContext(aws.BackgroundContext())
}

func (i *IMDSRoleProvider) RetrieveWithContext(ctx credentials.Context) (credentials.Value, error) {
	credsList, err := requestCredList(ctx, i.Client)
	if err != nil {
		return credentials.Value{ProviderName: ProviderName}, err
	}

	if len(credsList) == 0 {
		return credentials.Value{ProviderName: ProviderName}, awserr.New("EmptyEC2RoleList", "empty EC2 Role list", nil)
	}
	credsName := credsList[0]

	roleCreds, err := requestCred(ctx, i.Client, credsName)
	if err != nil {
		return credentials.Value{ProviderName: ProviderName}, err
	}

	i.SetExpiration(roleCreds.Expiration, i.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     roleCreds.AccessKeyID,
		SecretAccessKey: roleCreds.SecretAccessKey,
		SessionToken:    roleCreds.Token,
		ProviderName:    ProviderName,
	}, nil
}

// A ec2RoleCredRespBody provides the shape for unmarshaling credential
// request responses.
type ec2RoleCredRespBody struct {
	// Success State
	Expiration      time.Time
	AccessKeyID     string
	SecretAccessKey string
	Token           string

	// Error state
	Code    string
	Message string
}

func requestCredList(ctx aws.Context, client *ec2metadata.EC2Metadata) ([]string, error) {
	resp, err := client.GetMetadataWithContext(ctx, credentialPath)
	if err != nil {
		return nil, awserr.New("EC2RoleRequestError", "no EC2 instance role found", err)
	}

	credsList := []string{}
	s := bufio.NewScanner(strings.NewReader(resp))
	for s.Scan() {
		credsList = append(credsList, s.Text())
	}

	if err := s.Err(); err != nil {
		return nil, awserr.New(request.ErrCodeSerialization,
			"failed to read EC2 instance role from metadata service", err)
	}

	return credsList, nil
}

func requestCred(ctx aws.Context, client *ec2metadata.EC2Metadata, credsName string) (ec2RoleCredRespBody, error) {
	path, err := securejoin.SecureJoin(credentialPath, credsName)
	if err != nil {
		return ec2RoleCredRespBody{},
			awserr.New("EC2RoleRequestError",
				fmt.Sprintf("unable to securely load role %s credentials", credsName),
				err)
	}

	resp, err := client.GetMetadataWithContext(ctx, path)
	if err != nil {
		return ec2RoleCredRespBody{},
			awserr.New("EC2RoleRequestError",
				fmt.Sprintf("failed to get %s EC2 instance role credentials", credsName),
				err)
	}

	respCreds := ec2RoleCredRespBody{}
	if err := json.NewDecoder(strings.NewReader(resp)).Decode(&respCreds); err != nil {
		return ec2RoleCredRespBody{},
			awserr.New(request.ErrCodeSerialization,
				fmt.Sprintf("failed to decode %s EC2 instance role credentials", credsName),
				err)
	}

	if respCreds.Code != "Success" {
		// If an error code was returned something failed requesting the role.
		return ec2RoleCredRespBody{}, awserr.New(respCreds.Code, respCreds.Message, nil)
	}

	return respCreds, nil
}
