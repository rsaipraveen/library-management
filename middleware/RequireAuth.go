package middleware

import (
	"context"
	"fmt"
	"library-management/controllers"
	"library-management/initializers"
	"net/http"
	"os"

	// "go-jwt-gorm/initializers"
	// "go-jwt-gorm/models"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(c *gin.Context) {
	//fetch the cookie from the request
	tokenString, err := c.Cookie("access_token")
	if err != nil {
		log.Println("error no token string :", err)
		c.AbortWithStatus(http.StatusUnauthorized)
	}
	tokenMetaData, err := extractTokenMetadata(tokenString)
	if err != nil {
		log.Println(" Authorization token required ", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
		c.Abort()
		return
	}
	email, err2 := FetchAuth(tokenMetaData)
	if err2 != nil {
		log.Println("Token expired or invalid", err2)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired or invalid"})
		c.Abort()
		return
	}
	c.Set("email", email)
	c.Next()

}
func extractTokenMetadata(tokenString string) (*controllers.AccessDetails, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		log.Fatal(err)

	}

	claims, ok := token.Claims.(jwt.MapClaims)
	// if float64(time.Now().Unix()) > claims["exp"].(float64) {
	// 	//c.AbortWithStatus(http.StatusUnauthorized)

	// }

	if !ok || !token.Valid {
		log.Println("error claim ")
		return nil, fmt.Errorf("invalid token")
	}
	access_uuid, ok := claims["access_uuid"].(string)
	if !ok {
		log.Println("Failed to fetch uuid ")
		return nil, fmt.Errorf("access_uuid not found in token")
	}

	email, ok := claims["email"].(string)
	if !ok {
		log.Println("Failed to fetch uuid ")
		return nil, fmt.Errorf("email not found in token")
	}

	return &controllers.AccessDetails{
		AccessUuid: access_uuid,
		Email:      email,
	}, nil
}

func FetchAuth(metadata *controllers.AccessDetails) (string, error) {
	email, err := initializers.Client.Get(context.Background(), metadata.AccessUuid).Result()
	fmt.Println("result while fetching", email)
	fmt.Println("error while fetching  :", err)
	return email, err
}
