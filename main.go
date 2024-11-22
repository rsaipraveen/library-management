package main

import (
	"library-management/initializers"
	"library-management/internals/controllers"
	"library-management/internals/middleware"
	logger "library-management/loggers"

	"net/http"

	// "log"
	// "net/http"
	// "os"
	// "time"
	"github.com/gin-gonic/gin"
	//"github.com/sirupsen/logrus"
)

func main() {
	//fmt.Println("**** Library management *****")
	logger.Logger.Info("welcome to library management ")

	r := gin.Default()
	r.GET("/", hello)
	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.LoginUser)
	r.GET("/validate", middleware.AuthenticateMiddleware, controllers.Validate)
	r.POST("/books/createbook", controllers.AddBook)
	//r.GET("/books/getdetails", controllers.GetBookByBookId)
	protected := r.Group("/books")
	protected.Use(middleware.AuthenticateMiddleware)
	{
		protected.GET("/getallbooks", controllers.GetAll)
		protected.GET("/getdetails", controllers.GetBookByBookId)
	}
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
	Startup()

	// synchronize database table with model
	// initializers.SyncDatabase()
}

func Startup() {
	logger.Init()
}
