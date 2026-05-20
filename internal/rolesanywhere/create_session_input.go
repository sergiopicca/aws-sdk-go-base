package rolesanywhere

type CreateSessionInput struct {
	DurationsSeconds int    `json:"durationSeconds"`
	ProfileArn       string `json:"profileArn"`
	RoleArn          string `json:"roleArn"`
	SessionName      string `json:"sessionName"`
	TrustAnchorArn   string `json:"trustAnchorArn"`
	RoleSessionName  string `json:"roleSessionName"`
}
