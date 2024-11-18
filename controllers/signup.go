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

type UserResponse struct {
	Message      string `json:"error"`
	Error        bool   `json:"message,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}
type UserCred struct {
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

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrRedisKeyNotFound   = errors.New("redis key not found")
)

func SignUp(c *gin.Context) {
	ctx := context.Background()
	var user Users
	var response UserResponse
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
		response.Message = "user creation failed"
		response.Error = true
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
	InsertCredentialsToRedis(ctx, requestUser.Email, requestUser.Password)
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
	userCred, errRedis := AuthenticateFromRedis(ctx, credential)
	if errRedis != nil {
		switch errRedis {
		case ErrInvalidCredentials:
			response.Error = true
			response.ErrorMessage = " Invalid credentials "
			c.JSON(http.StatusBadRequest, response)
			return
		case ErrRedisKeyNotFound:
			fmt.Println("ErrRedisKeyNotFound case")
			AuthenticateFromDatabase(ctx, credential)
		default:
			log.Println("Redis error ", err)
		}
	} else {

		errToken := GenerateJWtokensAndStoreInCookie(c, credential.Email)
		if errToken != nil {
			log.Println(" failed to create token ", err)
			response.Error = true
			response.ErrorMessage = "Failed to create token"
			c.JSON(http.StatusBadRequest, response)
			return
		}
		response.Error = false
		response.Message = " Valid credentials ," + userCred.Email + " logged in successfully "
		c.JSON(http.StatusOK, response)
		return
	}

	// if cred is available is redis and compareHashPasswords returns error below code should not execute
	usercredDb, errDb := AuthenticateFromDatabase(ctx, credential)
	if errDb != nil {
		log.Println("invalid credentials :", errDb)
	}
	fmt.Println("usercredDb", usercredDb)
	errToken := GenerateJWtokensAndStoreInCookie(c, credential.Email)
	if errToken != nil {
		log.Println(" failed to create token ", err)
		response.Error = true
		response.ErrorMessage = "Failed to create token"
		c.JSON(http.StatusBadRequest, response)
		return
	}
	response.Message = "credentials are matched, Login successfully "
	c.JSON(http.StatusOK, response)
}

func AuthenticateFromRedis(ctx context.Context, credential LoginCredentials) (*UserCred, error) {

	if credential.Email == "" || credential.Password == "" {
		log.Println("Invalid credentials ")
		return nil, ErrInvalidCredentials
	}

	userKey := fmt.Sprintf("user:%s", credential.Email)
	result, err := initializers.Client.HGetAll(ctx, userKey).Result()
	fmt.Println("result :", result)
	if err != nil {

		return nil, errors.New("Redis error " + err.Error())
	}
	hashPassword, isExists := result["password"]
	if !isExists || hashPassword == "" {
		log.Println("user key not found in redis")
		return nil, ErrRedisKeyNotFound
	}
	err2 := compareHashPasswords(hashPassword, credential.Password)
	if err2 != nil {
		log.Println("invalid credentials", err2)
		return nil, ErrInvalidCredentials
	}
	// Add Id to below
	return &UserCred{
		Email:        credential.Email,
		HashPassword: hashPassword,
	}, nil

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
	return result["password"], nil
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

func InsertCredentialsToRedis(ctx context.Context, email, password string) error {
	userKey := fmt.Sprintf("user:%s", email)
	errRedis := initializers.Client.HSet(ctx, userKey, map[string]interface{}{
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

func GenerateJWtokensAndStoreInCookie(c *gin.Context, email string) error {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		//	"user_Id": userId,
		"sub": email,                            // subject ( user identifier )
		"exp": time.Now().Add(time.Hour).Unix(), // expiration time)
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
