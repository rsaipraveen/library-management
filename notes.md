

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


-> Implement roles for users in user_Profiles to implement authorization 

todo : 

//  Redis Implementation Issues:


No error handling for Redis connection failures
Missing retry mechanism
No TTL implementation
No cleanup strategy for stale data 
Add rate limiting with Redis