package rolesanywhere

import "github.com/aws/aws-sdk-go-v2/service/sts/types"

type CreateSessionOutput struct {
	AssumedRoleUser  types.AssumedRoleUser `json:"assumedRoleUser"`
	Credentials      types.Credentials     `json:"credentials"`
	PackedPolicySize int                   `json:"packedPolicySize"`
	SourceIdentity   string                `json:"sourceIdentity"`
	RoleArn          string                `json:"roleArn"`
	SubjectArn       string                `json:"subjectArn"`
}
