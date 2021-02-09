package main

import (
	"fmt"
	env "github.com/AdiSaripuloh/go-using-jwt/helpers"
	"github.com/AdiSaripuloh/go-using-jwt/models"
	"github.com/AdiSaripuloh/go-using-jwt/requests"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func init() {
	// TODO
	// - Create migration
}

func main() {
	port := env.Get("APP_PORT")
	router := gin.Default()

	api := router.Group("api")
	{
		v1 := api.Group("v1")
		{
			v1.POST("auth/login", loginHandler)
			v1.POST("auth/logout")
		}
	}

	if err := router.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

func ExtractToken(ctx *gin.Context) string {
	bearToken := ctx.GetHeader("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func verifyHandler(ctx *gin.Context) (*jwt.Token, error) {
	tokenString := ExtractToken(ctx)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func loginHandler(ctx *gin.Context) {
	var loginReq requests.LoginRequest
	if err := ctx.ShouldBindJSON(&loginReq); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":  "Unprocessable Entity",
			"message": "Invalid request",
		})
		return
	}

	// TODO
	// - Fetch data in storage
	// - Compare with data in storage
	user := &models.User{
		Uuid:     uuid.NewV4(),
		Username: loginReq.Username,
		Password: loginReq.Password,
	}

	// TODO: Change parameter to user from storage
	token, _ := CreateToken(user)
	ctx.JSON(http.StatusOK, gin.H{
		"status": "OK",
		"data":   &token,
	})
}

func CreateToken(user *models.User) (*models.Token, error) {
	tokenDetail := &models.Token{}
	tokenDetail.ExpiredAt = time.Now().Add(time.Minute * 15).Unix()
	tokenDetail.AccessUuid = uuid.NewV4().String()

	tokenDetail.RefreshExpiredAt = time.Now().Add(time.Hour * 24 * 7).Unix()
	tokenDetail.RefreshUuid = uuid.NewV4().String()

	var err error

	// Create Access Token
	accessClaims := jwt.MapClaims{}
	accessClaims["authorized"] = true
	accessClaims["accessUuid"] = tokenDetail.AccessUuid
	accessClaims["userId"] = user.Uuid
	accessClaims["exp"] = tokenDetail.ExpiredAt
	ac := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	tokenDetail.AccessToken, err = ac.SignedString([]byte(env.Get("ACCESS_TOKEN_KEY")))
	if err != nil {
		return nil, err
	}
	// Create Refresh Token
	refreshClaims := jwt.MapClaims{}
	refreshClaims["refreshUuid"] = tokenDetail.RefreshUuid
	refreshClaims["userId"] = user.Uuid
	refreshClaims["exp"] = tokenDetail.RefreshExpiredAt
	rc := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	tokenDetail.RefreshToken, err = rc.SignedString([]byte(env.Get("REFRESH_TOKEN_KEY")))
	if err != nil {
		return nil, err
	}
	return tokenDetail, nil
}
