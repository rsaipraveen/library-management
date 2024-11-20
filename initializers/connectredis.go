package initializers

import (
	"context"
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"
)

/*
	connect to redis
	check connection establishment through ping
	try inserting sample data and fetch
*/

var Client *redis.Client

func ConnectRedis() {
	Client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	pong, err := Client.Ping(context.Background()).Result()
	if err != nil {
		log.Println("redis connection establishment failed", err)
		return
	}
	fmt.Println(pong)
	// Output: PONG <nil>

}
