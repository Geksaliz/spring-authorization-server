### Auth endpoint
`http://localhost:8090/oauth2/authorize?response_type=code&client_id=taco-client&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/taco-client&scope=writeIngredients+deleteIngredients`
### Get token
`http://localhost:8090/oauth2/token -H"Content-type: application/x-www-form-urlencoded" -d"grant_type=authorization_code" -d"redirect_uri=http://127.0.0.1:8080/login/oauth2/code/taco-client" -d"code=$code" -u taco-client:07ac2000-b6c2-4b20-b1d3-2753a62e1be2`
### Get access token by refresh token
`http://localhost:8090/oauth2/token -H"Content-type: application/x-www-form-urlencoded" -d"grant_type=refresh_token&refresh_token=$token" -u taco-client:07ac2000-b6c2-4b20-b1d3-2753a62e1be2`