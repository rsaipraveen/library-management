package main

import (
	"fmt"
	"library-management/controllers"
	"library-management/initializers"
	"library-management/middleware"
	"net/http"

	// "log"
	// "net/http"
	// "os"
	// "time"

	"github.com/gin-gonic/gin"
	// "github.com/golang-jwt/jwt/v5"
	// "golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Println("**** Library management *****")

	// synchronize database table with model
	//initializers.SyncDatabase()

	r := gin.Default()
	r.GET("/", hello)
	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.LoginUser)
	r.GET("/validate", middleware.AuthMiddleware, controllers.Validate)
	r.Run()
}

func hello(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "welcome to library management",
	})
}
func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectDatabase()
	initializers.ConnectRedis()
}
