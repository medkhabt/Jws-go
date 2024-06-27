## Example : 
```go
// Don't add the private key directly in code! this is just an illustration example.
// Initialization of hmac with the private key
	jws.Init("dasfasdf")
// Generating a JWT token in a JWS structure with a 'iss':[id] and 'exp':cst. 
	token := jws.GenerateJWSToken(1)
// Verifies the signature of the token, return true if it's valid 
	if jws.VerifyJWSToken(token) {
// Get the id out of the token, it includes the verification too. 
		id, err := jws.GetIdFromJWS(token)
		if err != nil {
			fmt.Printf("error hmm interesting : [%s].\n", err)
		}
		fmt.Printf("verification successeded with id %d.\n", id)
	} else {
		fmt.Println("token not valid")
	}

```
