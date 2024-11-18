package controllers

import (
	"context"
	"errors"
	"fmt"
	models "library-management/Models"
	"library-management/initializers"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	message string
	Error   error
}
type UserResponse struct {
	Message      string
	Error        bool
	ErrorMessage string
}
type UserCred struct {
	ID           uint   `gorm:"column:id"`
	Email        string `gorm:"column:email"`
	HashPassword string `gorm:"column:password"`
}

type Users struct {
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	Phone        string `json:"phone"`
	AddressLine1 string `json:"address_line1"`
	AddressLine2 string `json:"address_line2"`
	City         string `json:"city"`
	State        string `json:"state"`
	Country      string `json:"country"`
	ZipCode      string `json:"zip_code"`
	UserType     string `json:"user_type"`
}

type LoginCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func SignUp(c *gin.Context) {
	var user Users
	var response Response
	errJson := c.BindJSON(&user)
	if errJson != nil {
		c.AbortWithError(400, errJson)
		return
	}
	fmt.Println("user :", user)

	// check if passwords is not ""
	// encrypt/hash password
	if err := user.HashPassword(); err != nil {
		log.Println("failed to hash password")
		return
	}

	requestUser := models.UserProfile{
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Email:        user.Email,
		Password:     user.Password, // here hashed password is stored
		Phone:        user.Phone,
		AddressLine1: user.AddressLine1,
		AddressLine2: user.AddressLine2,
		City:         user.City,
		State:        user.State,
		Country:      user.Country,
		ZipCode:      user.ZipCode,
		UserType:     user.UserType,
	}

	result := initializers.DB.Create(&requestUser)
	if result.Error != nil {
		fmt.Println("errror:", result.Error.Error())
		log.Println("failed to insert user profile into database", result.Error.Error())
		response.message = "user creation failed"
		response.Error = result.Error
		c.JSON(http.StatusBadRequest, response)
		return
	}
	// inserting username and hashedpassword to redis as key value pair
	userKey := fmt.Sprintf("user:%s", requestUser.Email)
	errRedis := initializers.Client.HSet(initializers.CTX, userKey, map[string]interface{}{
		"email":    requestUser.Email,
		"password": requestUser.Password,
	}).Err()

	if errRedis != nil {
		log.Println("failed to insert credentials in redis cache")
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "failed to insert credentials in redis",
		})
		return
	}
	InsertCredentialsToRedis(requestUser.Email, requestUser.Password)
	// send success message
	fmt.Println("response result :", result)
}

/*
Login
fetch email id and password from request
bind credentails to struct
select statement to fetch password based on email id

use bcrypt compare hash password
if both are same , send login successfully
create jwt token and send jwt token
*/
func Login(c *gin.Context) {
	// Explicitly map struct fields to database column names using gorm tags as it was not able to fetch and deteails properly

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	var response UserResponse
	// var user UserCred               // for storing result from db
	var credential LoginCredentials // storing / binding data from gin request
	err := c.BindJSON(&credential)
	if err != nil {
		response.Error = true
		response.ErrorMessage = " invalid request format "
		c.JSON(http.StatusBadRequest, response)
		return
	}
	// hashpwd, err2 := FetchDetailsFromRedis(ctx, credential)
	// if err2 != nil {
	// 	// TODO : check error scenarios
	// 	log.Println("failed to fetch details from redis", err2)

	// }
	// fmt.Println(" redis nil :: ", err == redis.Nil)
	// if hashpwd != "" {
	// 	err3 := compareHashPasswords(hashpwd, credential.Password)
	// 	if err3 != nil {
	// 		log.Println(" passwords mismatched , invalid credentials ")
	// 		response.Error = true
	// 		response.ErrorMessage = " invalid credentials , please check"
	// 		c.JSON(http.StatusBadRequest, response)
	// 		return
	// 	}
	// 	response.Message = "credentials are matched"
	// 	response.ErrorMessage = ""
	// 	errToken := GenerateJWtokensAndStoreInCookie(c, user.ID, credential.Email)

	// 	if errToken != nil {
	// 		log.Println("token creation failed")
	// 	}
	// 	c.JSON(http.StatusOK, response)
	// 	return
	// }

	usercred, err3 := AuthenticateFromRedis(ctx, credential)
	if err3 != nil {
		response.Error = true
		response.ErrorMessage = " invalid request format "
		c.JSON(http.StatusBadRequest, response)
		return
	}
	fmt.Println("u::", usercred)
	fmt.Println("e ::", err3)
	response.Message = "credentials are matched"
	response.ErrorMessage = ""
	c.JSON(http.StatusOK, response)

	// if cred is available is redis and compareHashPasswords returns error below code should not execute

	// result := initializers.DB.Table("user_profiles").Select("ID, password").Where("email = ?", credential.Email).Scan(&user)
	// fmt.Println("now validating data from postgres")
	// if result.Error != nil {
	// 	response.Error = true
	// 	response.ErrorMessage = "failed to process request "
	// 	c.JSON(http.StatusBadRequest, response)
	// 	return
	// }

	// if result.RowsAffected == 0 {
	// 	response.Error = true
	// 	response.ErrorMessage = "invalid email or password "
	// 	c.JSON(http.StatusUnauthorized, response)
	// 	return
	// }

	// fmt.Println(" user ", user)
	// errHash := compareHashPasswords(user.HashPassword, credential.Password)
	// // errHash := bcrypt.CompareHashAndPassword([]byte(user.HashPassword), []byte(credential.Password))
	// if errHash != nil {
	// 	response.Error = true
	// 	response.ErrorMessage = "invalid credentails,  password mismatch "
	// 	c.JSON(http.StatusBadRequest, response)
	// 	return
	//}
	// push data to redis
	// InsertCredentialsToRedis(credential.Email, user.HashPassword)
	// response.Message = "credentials are matched"

	// errToken := GenerateJWtokensAndStoreInCookie(c, user.ID, credential.Email)

	// if errToken != nil {
	// 	log.Println("token creation failed")
	// }

	// c.JSON(http.StatusOK, response)
}

func AuthenticateFromRedis(ctx context.Context, credential LoginCredentials) (*UserCred, error) {
	hashPwd, err := FetchDetailsFromRedis(ctx, credential)

	if err != nil || hashPwd == "" {
		log.Println("error found ")
		return nil, redis.Nil
	}
	err2 := compareHashPasswords(hashPwd, credential.Password)
	if err2 != nil {
		log.Println("invalid credentials", err2)
		return nil, errors.New("invalid credentials ")
	}
	// Add Id to below
	return &UserCred{
		Email:        credential.Email,
		HashPassword: hashPwd,
	}, nil
}

func AuthenticateFromDatabase(ctx context.Context, credential LoginCredentials) (*UserCred, error) {
	var userCred *UserCred
	result := initializers.DB.Table("user_profiles").Select("id,email, password").Where("email = ?", credential.Email).Scan(&userCred)

	if result.Error != nil {
		return nil, errors.New("unable to fetch details from database")
	}

	if result.RowsAffected == 0 {
		return nil, errors.New("unable to fetch details from database")
	}

	errHash := compareHashPasswords(userCred.HashPassword, credential.Password)
	// errHash := bcrypt.CompareHashAndPassword([]byte(user.HashPassword), []byte(credential.Password))
	if errHash != nil {
		return nil, errors.New("invalid credentials")
	}
	fmt.Println("user credentials", userCred)
	return userCred, nil
}
func (user *Users) HashPassword() error {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Println("failed to hash password")
		return err
	}

	user.Password = string(hash)
	return nil
}

func InsertCredentialsToRedis(email, password string) error {
	userKey := fmt.Sprintf("user:%s", email)
	errRedis := initializers.Client.HSet(initializers.CTX, userKey, map[string]interface{}{
		"email":    email,
		"password": password,
	}).Err()

	if errRedis != nil {
		log.Println("failed to insert credentials in redis cache")
		return errRedis
	}
	log.Println("successfully inserted credentials into redis")
	return nil
}

func compareHashPasswords(hashPwd, pwd string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))
}

func FetchDetailsFromRedis(ctx context.Context, credential LoginCredentials) (string, error) {
	userKey := fmt.Sprintf("user:%s", credential.Email)
	result, err := initializers.Client.HGetAll(initializers.CTX, userKey).Result()
	fmt.Println("error :", err == redis.Nil)
	if err != nil {
		log.Println("error while fetching details from redis ", err)
		return "", err
	}
	fmt.Println("result :::", result, err)
	// if len(result) == 0 {
	// 	return nil, redis.Nil
	// }
	return result["password"], nil
}

func GenerateJWtokensAndStoreInCookie(c *gin.Context, userId uint, email string) error {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_Id": userId,
		"sub":     email,                            // subject ( user identifier )
		"exp":     time.Now().Add(time.Hour).Unix(), // expiration time)
	})

	tokenString, err := token.SignedString([]byte("owgeg35g35hgnwh1fh"))
	if err != nil {
		log.Println("failed to create token string ", err)
		return err
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	return nil
}
