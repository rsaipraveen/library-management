package middleware

import (
	"context"
	"errors"
	"fmt"
	"time"

	"library-management/initializers"
	logger "library-management/loggers"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessDetails struct {
	AccessUuid string
	Email      string
}

type RefreshDetails struct {
	RefreshUuid string
	Email       string
}
type TokenPair struct {
	AccessToken  string
	AccessUuid   string
	AtExpires    int64
	RefreshToken string
	RefreshUuid  string
	RtExpires    int64
}

func GenerateTokensAndSaveInCookies(c *gin.Context, email string) error {
	tokenPair, err := CreateTokenPair(email)
	if err != nil {
		logger.Logger.Error("failed to create tokens pairs :", err)
		return err
	}
	err2 := SaveTokenPair(tokenPair, email)
	if err2 != nil {
		logger.Logger.Error("failed to save tokens in redis :", err2)
		return err2
	}
	c.SetCookie("access_token", tokenPair.AccessToken, 3600, "/", "localhost", false, true)
	c.SetCookie("refresh_token", tokenPair.RefreshToken, 7*24*3600, "/", "localhost", false, true)
	return nil

}

func CreateTokenPair(email string) (*TokenPair, error) {
	var err error
	token := &TokenPair{
		AtExpires:   time.Now().Add(time.Minute * 15).Unix(),   // Access token expires in 15 mins
		RtExpires:   time.Now().Add(time.Hour * 24 * 7).Unix(), // Refresh token expires in 7 days
		AccessUuid:  uuid.New().String(),                       // used for storing meta data in redis
		RefreshUuid: uuid.New().String(),                       // used for storing meta data in redis
	}

	atClaims := jwt.MapClaims{
		"authorized":  true,
		"access_uuid": token.AccessUuid,
		"email":       email,
		"exp":         token.AtExpires,
	}
	tokenVal := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	token.AccessToken, err = tokenVal.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		log.Println("signing of AT token failed ", err)
		return nil, err
	}
	// Creating Refresh Token
	rtClaims := jwt.MapClaims{
		"refresh_uuid": token.RefreshUuid,
		"email":        email,
		"exp":          token.RtExpires,
	}
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	token.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		logger.Logger.Error("signing of token failed with error :", err)
		return nil, err
	}
	return token, nil
}

func SaveTokenPair(tokenObj *TokenPair, email string) error {
	at := time.Unix(tokenObj.AtExpires, 0)
	rt := time.Unix(tokenObj.RtExpires, 0)
	now := time.Now()
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Store access token metadata
	err := initializers.Client.Set(ctx, tokenObj.AccessUuid, email, at.Sub(now)).Err()
	if err != nil {
		logger.Logger.Error("failed to insert access token in redis : ", err)
		return err
	}

	// Store refresh token metadata
	err = initializers.Client.Set(ctx, tokenObj.RefreshUuid, email, rt.Sub(now)).Err()
	if err != nil {
		logger.Logger.Error("failed to insert refresh token in redis : ", err)
		return err
	}
	return nil
}

func AuthenticateMiddleware(c *gin.Context) {
	//fetch the cookie from the request
	tokenString, err := c.Cookie("access_token")
	if err != nil {
		logger.Logger.Error("failed to fetch access token : ", err)
		RefreshTokenFlow(c)
		return
	}
	accessTokenMetaData, err := extractAccessTokenMetadata(tokenString)
	if err != nil {
		logger.Logger.Error("access token meta data failed :", err)
		RefreshTokenFlow(c)
		return
	}
	email, err2 := FetchAuth(accessTokenMetaData)
	if err2 != nil {
		log.Println("Token expired or invalid", err2)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired or invalid"})
		c.Abort()
		return
	}
	c.Set("email", email)
	c.Next()
}

func extractAccessTokenMetadata(tokenString string) (*AccessDetails, error) {
	secret := os.Getenv("ACCESS_SECRET")
	if secret == "" {
		logger.Logger.Error("failed to retrive refresh secret")
		return nil, errors.New(" ACCESS_SECRET is not set ")
	}
	claims, err := extractTokenMetadata(tokenString, secret, []string{"access_uuid", "email"})
	if err != nil {
		logger.Logger.Error("failed to extract access token meta data :", err)
		return nil, err
	}

	return &AccessDetails{
		AccessUuid: claims["access_uuid"].(string),
		Email:      claims["email"].(string),
	}, nil
}

func extractRefreshTokenMetadata(refreshString string) (*RefreshDetails, error) {
	secret := os.Getenv("REFRESH_SECRET")

	if secret == "" {
		logger.Logger.Error("failed to retrive refresh secret")
		return nil, errors.New(" REFRESH_SECRET is not set ")
	}
	claims, err := extractTokenMetadata(refreshString, secret, []string{"refresh_uuid", "email"})

	if err != nil {
		logger.Logger.Error("failed to extract refresh token meta data :", err)
		return nil, err
	}

	return &RefreshDetails{
		RefreshUuid: claims["refresh_uuid"].(string),
		Email:       claims["email"].(string),
	}, nil
}

func extractTokenMetadata(tokenString string, secret string, expectedClaims []string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})

	if err != nil {
		logger.Logger.Error("token parsing failed ", err)
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		return nil, errors.New("token expired ")

	}

	for _, claim := range expectedClaims {
		if _, ok := claims[claim]; !ok {
			return nil, fmt.Errorf("missing required claim: %s", claim)
		}
	}
	return claims, nil
}

func RefreshTokenFlow(c *gin.Context) {
	fmt.Println("inside refresh token flow creations ")
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		logger.Logger.Error("Refresh token missing / not found ")
		c.AbortWithStatusJSON(400, gin.H{
			"message": "Refresh token missing / not found ",
		})
		return
	}

	refreshTokenDetails, err2 := extractRefreshTokenMetadata(refreshToken)
	if err2 != nil {
		logger.Logger.Error("failed to extract refresh meta data : ", err2)
		c.AbortWithStatusJSON(400, gin.H{
			"message": "Failed to extract refresh token meta data ",
		})
		return
	}

	err3 := GenerateTokensAndSaveInCookies(c, refreshTokenDetails.Email)
	if err3 != nil {
		logger.Logger.Error("failed to create new tokens ", err3)
		return
	}
	c.Set("email", refreshTokenDetails.Email)
}

func FetchAuth(metadata *AccessDetails) (string, error) {
	email, err := initializers.Client.Get(context.Background(), metadata.AccessUuid).Result()
	return email, err

}
