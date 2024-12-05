package entity

type LoginRequest struct {
	Login string `json:"login"`
	GUID  string `json:"guid"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
