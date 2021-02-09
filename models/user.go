package models

import "github.com/twinj/uuid"

type User struct {
	Uuid     uuid.UUID
	Username string
	Password string
}

type Token struct {
	AccessToken      string `json:"accessToken"`
	RefreshToken     string `json:"refreshToken"`
	AccessUuid       string `json:"accessUuid"`
	RefreshUuid      string `json:"refreshUuid"`
	ExpiredAt        int64  `json:"atExpires"`
	RefreshExpiredAt int64  `json:"refreshExpiredAt"`
}
