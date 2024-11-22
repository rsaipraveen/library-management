

Redis : 


	signup : 
		if : insertion successful to pg 
			insert username and hashedpassword to redis 
		
		else skip insertion of credentials 
	
	Login : 
        validate credentials with email as key in redis 
            if :credentials exists in redis
                validate credentials 
                    check if result is nil / we get some data 
                    hashpassword is stored in redis 
                    so compare hashedpassword from redis and password sent from "/login" api 
                    if password matches send login successful message
                        else send invalid credentials message
            else 
                fetch credentials from pgsql 

Login Request
│
├── Valid JSON? → No → Return 400
│
├── Redis Auth
│   ├── Success → Generate Token → Return 200
│   ├── Invalid Credentials → Return 401
│   └── Key Not Found → Try Database
│
└── Database Auth
    ├── Success → Generate Token → Return 200
    └── Failure → Return 401

-> Implement roles for users in user_Profiles to implement authorization 

todo : 

//  Redis Implementation Issues:


No error handling for Redis connection failures
Missing retry mechanism
No TTL implementation
No cleanup strategy for stale data 
Add rate limiting with Redis

Login flow with JWT 
1. User logs in
   ↓
2. Server creates JWT
   ↓
3. Server stores token metadata in Redis
   ↓
4. Server sets token in cookie
   ↓
5. Browser automatically stores cookie
   ↓
6. Browser automatically sends cookie with every request
   ↓
7. Server validates token against Redis on each request



19/11/2024 
Improved Context Management:

Increased timeout duration for the entire operation
Separate context for background caching
Context propagation to token generation




NOTES 


1. why InsertCredentialsToRedis is moved to AuthenticateUser() 

    Moved Redis caching to a background goroutine
    Authentication success doesn't depend on cache success
    Better performance for end users
    

  note :  Caching credentials in the background is a trade-off between performance and consistency. It's most effective when fast user responses are prioritized, and Redis is a non-critical optimization layer. However, for high-reliability systems where caching must be accurate and timely, blocking the response to ensure Redis consistency might be preferable.



  


  --------------------------


  Authenticate middleware functionality 

  step 1 : fetch accesstoken from cookie 
  step 2 : Present : extract metadata and email id from redis 
  step 3: if no access token : call refresh token to create both tokens ( access and refresh tokens )



  step 2 : extract metadata and email id from redis 

   step a : first validate jwt token 
      if token is valid 
      fetch access_uuid and email from redis 




// Issues 

   1. check how to handle concurrent login handle issues 
   2. check context related issues in middleware
   3. Implement rate limiting 