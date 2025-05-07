package keycloak

import (
	"encoding/json"
	"fmt"
	"github.com/getevo/evo/v2"
	"github.com/getevo/evo/v2/lib/curl"
	"github.com/getevo/evo/v2/lib/log"
	"github.com/getevo/evo/v2/lib/settings"
	"github.com/getevo/evo/v2/lib/text"
	"github.com/go-jose/go-jose/v4"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/tidwall/gjson"
)

var conn *Connection
var timeout = 5 * time.Second

func GetInstance() *Connection {
	return conn
}

func (connection *Connection) UpdateAdminToken(realm string) (*JWT, error) {
	var endpoint = "auth"
	if connection.Settings.Version >= 18 {
		endpoint = ""
	}
	result, err := connection.Post(endpoint, "/protocol/openid-connect/token", curl.Param{
		"client_id":     connection.Settings.Client,
		"client_secret": connection.Settings.ClientSecret,
		"grant_type":    "client_credentials",
	}, timeout)
	if err != nil {
		return nil, err
	}
	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return nil, fmt.Errorf(parsed.Get("error").String())
	}
	var j JWT
	err = json.Unmarshal(result.Bytes(), &j)
	if err != nil {
		return nil, err
	}
	connection.Admin = &j
	return &j, nil
}

// GetUsers retrieves a list of users from the server.
//
// Parameters:
//   - max: The maximum number of users to retrieve (limited to 100).
//   - offset: The offset value for pagination.
//   - extra: Additional parameters to include in the request.
//
// Returns:
//   - users: The list of User objects retrieved from the server.
//   - error: Any error that occurred during the request.
//
// The User struct represents a user in the system and contains information such as ID, username,
// first name, last name, email, and more.
//
// The curl.QueryParam type is a map of string keys to any values, representing the additional parameters
// to include in the request.
//
// The curl.Header type is a map of string keys to string values, representing HTTP header fields.
// The Clone method is used to create a copy of a header instance.
func (connection *Connection) GetUsers(max int, offset int, extra map[string]string) ([]UserInstance, error) {
	var users []UserInstance
	if max > 100 {
		max = 100
	}
	var params = curl.QueryParam{
		"max":   max,
		"first": offset,
	}
	for k, v := range extra {
		params[k] = v
	}
	result, err := connection.Get("/admin", "/users", curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, params)

	if err != nil {
		return users, err
	}
	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return nil, fmt.Errorf(parsed.Get("error").String())
	}
	err = json.Unmarshal(result.Bytes(), &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

// Block sets the Enabled field of the user to false and saves the changes using the EditUser method of the Connection struct.
// It takes a pointer to a User struct as a parameter and returns an error if there is any issue editing the user.
// Example usage:
//
//	conn := &Connection{}
//	user := &User{ID: "user1", Enabled: true}
//	err := conn.Block(user)
//	if err != nil {
//	    fmt.Println("Error blocking user:", err)
//	}
//
// The User struct should have the following fields:
//
//	ID               string               `json:"id" form:"id"`
//	Username         string               `json:"username" form:"username"`
//	FirstName        string               `json:"firstName" form:"firstName"`
//	LastName         string               `json:"lastName" form:"lastName"`
//	Email            string               `json:"email" form:"email"`
//	CreatedAt        int64                `json:"createdTimestamp"`
//	RegistrationDate time.Time            `json:"-"`
//	IsAdmin          bool                 `json:"-" form:"is_admin"`
//	EmailVerified    bool                 `json:"emailVerified"`
//	Enabled          bool                 `json:"enabled" form:"enabled"`
//	Attributes       Attributes           `json:"attributes"`
//	Credentials      *[]Credentials       `json:"credentials,omitempty"`
//	RequiredActions  *[]string            `json:"requiredActions,omitempty"`
//	Access           *map[string]bool     `json:"access,omitempty"`
//	ClientRoles      *map[string][]string `json:"clientRoles,omitempty"`
//	RealmRoles       *[]string            `json:"realmRoles,omitempty"`
//	Groups           *[]string            `json:"groups,omitempty"`
//	FederationLink   *string              `json:"federationLink,omitempty"`
//	Totp             *bool                `json:"totp,omitempty"`
//	connection       *Connection
func (connection *Connection) Block(user *UserInstance) error {
	user.Enabled = false
	return connection.EditUser(user)
}

/*func (c *Connection) RefreshToken(input *JWT) (*JWT,error) {
	input.
}*/

// Login sends a POST request to the specified endpoint with the provided username, password, client ID, client secret, and grant type.
// It returns a JWT (JSON Web Token) and an error if any.
// The JWT contains access token, ID token, expiration duration, refresh expiration duration, refresh token, token type, not before policy, session state, and scope.
func (connection *Connection) Login(username, password string) (*JWT, error) {
	var endpoint = "auth"
	if connection.Settings.Version >= 18 {
		endpoint = ""
	}
	result, err := connection.Post(endpoint, "/protocol/openid-connect/token", curl.Param{
		"username":      username,
		"password":      password,
		"client_id":     connection.Settings.Client,
		"client_secret": connection.Settings.ClientSecret,
		"grant_type":    "password",
	})
	if err != nil {
		return nil, err
	}

	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return nil, fmt.Errorf(parsed.Get("error").String())
	}
	var j JWT
	err = json.Unmarshal(result.Bytes(), &j)
	if err != nil {
		return nil, err
	}
	//c.Admin = &jwt
	return &j, nil
}

// ChangePassword updates the password for a given user in the specified realm.
// It sends a PUT request to the server's reset-password endpoint, providing the user ID and new password as JSON payload.
// The access token of the admin user is used for authentication.
// If the request is successful and the response status code is 204, it returns nil.
// If the response body contains an error message, it returns an error with the error message.
// If any error occurs during the request or parsing of the response, it returns the error.
// If the response status code is not 204 and the error message is empty, it returns an error message "unable to change password".
func (connection *Connection) ChangePassword(user *UserInstance, password string) error {
	var url = connection.Settings.Server + "/admin/realms/" + connection.Settings.Realm + "/users/" + user.UUID + "/reset-password"
	resp, err := curl.Put(url, curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, curl.BodyJSON(
		map[string]interface{}{
			"temporary": false,
			"type":      "password",
			"value":     password,
		},
	), timeout)
	if err != nil {
		return err
	}
	if resp.Response().StatusCode == 204 {
		return nil
	}
	var result = gjson.Parse(resp.String())
	if result.Get("error").String() != "" {
		return fmt.Errorf(result.Get("error").String())
	}

	return fmt.Errorf("unable to change password")
}

func (connection *Connection) SetCredentials(user *UserInstance, credentials Credentials) error {
	var url = connection.Settings.Server + "/admin/realms/" + connection.Settings.Realm + "/users/" + user.UUID + "/reset-password"
	resp, err := curl.Put(url, curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, curl.BodyJSON(
		credentials,
	), timeout)
	if err != nil {
		return err
	}
	if resp.Response().StatusCode == 204 {
		return nil
	}
	var result = gjson.Parse(resp.String())
	if result.Get("error").String() != "" {
		return fmt.Errorf(result.Get("error").String())
	}

	return fmt.Errorf("unable to change password")
}

// ResetPasswordOtpIsValid checks if the provided OTP (One-Time Password) is valid for a given user.
// It queries the database for a reset entry matching the user ID and OTP, and checks if it was created within the last hour.
// If a matching reset entry is found, the method returns true; otherwise, it returns false.
//
// Parameters:
//   - otp: The One-Time Password to validate.
//   - user: The user for whom the OTP is being validated.
//
// Returns:
//   - bool: true if the OTP is valid, false otherwise.
func (connection *Connection) ResetPasswordOtpIsValid(otp string, user *UserInstance) bool {
	var reset Reset
	if evo.GetDBO().Where("uuid = ? AND otp = ? AND created_at >  DATE_SUB(NOW(),INTERVAL 1 HOUR)", user.UUID, otp).Take(&reset).RowsAffected == 0 {
		return false
	}

	return true
}

// ResetPasswordRequest sends a request to reset the password for a user.
// It creates a new Reset struct with the given user ID and a random OTP (One-Time Password).
// The Used field is set to false.
// The Reset struct is saved in the database using the GetDBO() function from evo package.
// If an error occurs during the database save operation, it is returned along with the reset struct.
// Otherwise, the reset struct and nil error are returned.
func (connection *Connection) ResetPasswordRequest(user *UserInstance) (Reset, error) {
	var reset = Reset{
		IDUser: user.UUID,
		OTP:    text.Random(32),
		Used:   false,
	}
	var err = evo.GetDBO().Create(&reset).Error
	return reset, err
}

// CreateUser creates a new user in the system using the provided user object.
// It takes a reference to a Connection object and a pointer to a User object.
// It returns an error if any during the creation process.
func (connection *Connection) CreateUser(user *UserInstance) error {
	var endpoint = "auth/admin"
	if connection.Settings.Version >= 18 {
		endpoint = "admin"
	}
	result, err := connection.Post(endpoint, "/users", curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, curl.BodyJSON(user), timeout)

	if err != nil && err.Error() != "unexpected end of JSON input" {
		return err
	}
	if result.Response().StatusCode == 409 {
		return fmt.Errorf("duplicate user")
	}

	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return fmt.Errorf(parsed.Get("error").String())
	}
	if result.Response().StatusCode > 299 {
		return fmt.Errorf("unable to create user")
	}
	err = json.Unmarshal(result.Bytes(), &user)
	if err != nil {
		return err
	}
	return nil
}

// RefreshToken sends a request to refresh the JWT token using the provided refresh token.
func (connection *Connection) RefreshToken(refreshToken string) (*JWT, error) {
	var endpoint = "auth"
	if connection.Settings.Version >= 18 {
		endpoint = ""
	}
	result, err := connection.Post(endpoint, "/protocol/openid-connect/token", curl.Param{
		"client_id":     connection.Settings.Client,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_secret": connection.Settings.ClientSecret,
	})

	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return nil, fmt.Errorf(parsed.Get("error").String())
	}
	var j JWT
	err = json.Unmarshal(result.Bytes(), &j)
	if err != nil {
		return nil, err
	}

	return &j, nil
}

// EditUser modifies the information of a user in the system.
//
// The user parameter should be a pointer to a User object containing the updated information.
// Returns an error if there is a problem with the API request or if the API returns an error message.
// If the API request is successful, the User object in the connection object is updated with the modified information.
func (connection *Connection) EditUser(user *UserInstance) error {
	var endpoint = "auth/admin"
	if connection.Settings.Version >= 18 {
		endpoint = "admin"
	}
	result, err := connection.Put(endpoint, "/users/"+user.UUID, curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, curl.BodyJSON(user))
	if err != nil {
		return err
	}

	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return fmt.Errorf(parsed.Get("error").String())
	}

	return nil
}

func (connection *Connection) DeleteUser(uuid string) error {
	var endpoint = "auth/admin"
	if connection.Settings.Version >= 18 {
		endpoint = "admin"
	}
	result, err := connection.Delete(endpoint, "/users/"+uuid, curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	})
	if err != nil {
		return err
	}

	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return fmt.Errorf(parsed.Get("error").String())
	}

	return nil
}

// GetUser retrieves a user with the specified ID from the admin API.
// It returns the user object and any error encountered.
func (connection *Connection) GetUser(id string) (UserInstance, error) {
	var user UserInstance
	var endpoint = "auth/admin"
	if connection.Settings.Version >= 18 {
		endpoint = "/admin"
	}
	result, err := connection.Get(endpoint, "/users/"+id, curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	})
	if err != nil {
		return user, err
	}
	if msg := gjson.Parse(result.String()).Get("error").String(); msg != "" {
		return user, fmt.Errorf(msg)
	}
	err = json.Unmarshal(result.Bytes(), &user)
	if err != nil {
		return user, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user from the system by their email address.
// The email address is passed as a string argument.
// It returns a User struct representing the user found, and an error if any.
// If the user is not found, it returns an error "user not found".
// The returned User struct contains various user details such as ID, username, first name, last name, email, etc.
// An example usage may be:
//
//	user, err := connection.GetUserByEmail("test@example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(user.Username)
func (connection *Connection) GetUserByEmail(email string) (UserInstance, error) {
	var user UserInstance
	result, err := connection.Get("/admin", "/users?email="+email+"&max=1", curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	})
	if err != nil {
		return user, err
	}
	if msg := gjson.Parse(result.String()).Get("error").String(); msg != "" {
		return user, fmt.Errorf(msg)
	}
	res := result.String()

	data := gjson.Parse(res)
	if len(data.Array()) == 0 {
		return user, fmt.Errorf("user not found")
	}
	err = json.Unmarshal([]byte(data.Get("0").String()), &user)
	if err != nil {
		return user, err
	}

	return user, nil
}

// Debug sets the debug state of the Connection.
func (connection *Connection) Debug(state bool) {
	connection.Settings.Debug = state
}

// Put sends a PUT request to the specified endpoint with the provided query strings and data. It returns a curl.Resp and an error.
// Parameters:
// - endpoint: The endpoint path to send the request to.
// - query: The query string to be appended to the endpoint URL.
// - data: Optional data to be included in the request body.
// Returns:
// - *curl.Resp: The response from the PUT request.
// - error: Any error that occurred during the request.
func (connection *Connection) Put(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = append(data, timeout)
	var url = strings.Trim(connection.Settings.Server+endpoint, "/") + "/realms/" + connection.Settings.Realm + query
	resp, err := curl.Put(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	resp, err = handleRedirect(resp)
	if err != nil {
		return nil, err
	}
	if resp.Response().StatusCode == 204 {
		return resp, nil
	}
	return resp, nil
}

func (connection *Connection) Delete(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = append(data, timeout)
	var url = strings.Trim(connection.Settings.Server+endpoint, "/") + "/realms/" + connection.Settings.Realm + query
	resp, err := curl.Delete(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	resp, err = handleRedirect(resp)
	if err != nil {
		return nil, err
	}
	if resp.Response().StatusCode == 204 {
		return resp, nil
	}
	return resp, nil
}

// Post sends a POST request to the specified endpoint with optional query parameters and data. It returns the response and an error if any.
func (connection *Connection) Post(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = append(data, timeout)
	var url = strings.Trim(connection.Settings.Server+endpoint, "/") + "/realms/" + connection.Settings.Realm + query
	resp, err := curl.Post(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	resp, err = handleRedirect(resp)
	if resp.Response().StatusCode == 204 {
		return resp, nil
	}
	return resp, nil
}

// handleRedirect redirects the response to the location specified in the "location" header, if present.
// It uses the curl.Get function to make a new request to the location. If there is an error during the request, it returns nil and the error.
// If there is no "location" header or there is no error, it returns the original response and nil error.
func handleRedirect(resp *curl.Resp) (*curl.Resp, error) {
	var err error
	if resp.Response().Header.Get("location") != "" {
		resp, err = curl.Get(resp.Response().Header.Get("location"), resp.Request().Header)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// Get method sends a GET request to the specified endpoint with optional query parameters and data.
//
// Parameters:
// - endpoint: the endpoint URL string to send the request to.
// - query: the query string to include in the request URL.
// - data: optional variadic parameter to include data in the request body.
//
// Returns:
// - *curl.Resp: the response object containing the HTTP response information.
// - error: any error that occurred during the request.
func (connection *Connection) Get(endpoint string, query string, data ...interface{}) (*curl.Resp, error) {
	data = append(data, timeout)
	var url = strings.Trim(connection.Settings.Server+endpoint, "/") + "/realms/" + connection.Settings.Realm + query
	resp, err := curl.Get(url, data...)
	if err != nil {
		return nil, err
	}
	if connection.Settings.Debug {
		fmt.Println(resp.Dump())
	}
	resp, err = handleRedirect(resp)
	return resp, nil
}

// VerifyOffline verifies the offline access token and extracts the claims from it.
// It takes the accessToken string and claims interface{}, and returns a Spec and an error.
//
// Finally, the function returns the extracted Spec and nil error.
func (connection *Connection) VerifyOffline(accessToken string, claims interface{}) (Spec, error) {
	var spec Spec

	token, err := jwt.ParseSigned(accessToken, []jose.SignatureAlgorithm{jose.ES512, jose.HS384, jose.HS256, jose.RS256, jose.SignatureAlgorithm(jose.RSA_OAEP), jose.ES256})
	if err != nil {
		log.Error(err)
		return spec, err
	}
	err = token.Claims(connection.Certificate, &spec)
	if spec.Iat != nil {
		spec.AuthTime = int(time.Now().Unix()) - *spec.Iat
	}

	if err != nil {
		return spec, err
	}
	if claims != nil {
		err := token.Claims(connection.Certificate, claims)
		if err != nil {
			return Spec{}, err
		}
	}
	return spec, nil
}

// ParseToken parses the access token and verifies it online or offline based on the strict flag.
func (connection *Connection) ParseToken(accessToken string, claims interface{}, strict bool) (Spec, error) {
	var spec Spec
	if strict {
		var err = connection.VerifyOnline(accessToken)
		if err != nil {
			return spec, err
		}
	}

	return connection.VerifyOffline(accessToken, claims)
}

// VerifyOnline verifies if a token is valid by making a POST request to the token introspection endpoint.
// It takes a token as input and returns an error if the token is invalid.
func (connection *Connection) VerifyOnline(token string) error {
	var endpoint = "auth"
	if connection.Settings.Version >= 18 {
		endpoint = ""
	}
	var result, err = connection.Post(endpoint, "/protocol/openid-connect/token/introspect", curl.Param{
		"client_id":     connection.Settings.Client,
		"client_secret": connection.Settings.ClientSecret,
		"token":         token,
	})
	if err != nil {
		return err
	}
	var parsed = gjson.Parse(result.String())
	if !parsed.Get("active").Bool() {
		return fmt.Errorf("invalid user access token")
	}
	if parsed.Get("error").String() != "" {
		return fmt.Errorf(parsed.Get("error").String())
	}

	return nil
}

// Impersonate impersonates a user and obtains a JWT token for the specified user.
//
// Parameters:
//   - user: The user object representing the user to impersonate.
//   - internalToken: Flag indicating whether to request an access token or a refresh token.
//     When set to true, a refresh token will be requested. Otherwise, an access token will be requested.
//
// Returns:
// - *JWT: The JWT token obtained after successful impersonation.
// - error: An error if an issue occurs during the impersonation process.
//
// Example usage:
// user := &User{ID: "user123"}
// jwtToken, err := connection.Impersonate(user, true)
//
//	if err != nil {
//	    fmt.Println("Failed to impersonate user:", err)
//	    return
//	}
//
// fmt.Println("Impersonation successful. JWT token:", jwtToken)
//
// Note: The User and JWT types are defined in the code, please refer to their declarations for details.
func (connection *Connection) Impersonate(user *UserInstance, internalToken bool) (*JWT, error) {
	var requestTokenType = "urn:ietf:params:oauth:token-type:access_token"
	if internalToken {
		requestTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	}
	var endpoint = "auth"
	if connection.Settings.Version >= 18 {
		endpoint = ""
	}
	result, err := connection.Post(endpoint, "/protocol/openid-connect/token", curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, curl.Param{
		"requested_subject":    user.UUID,
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"client_id":            connection.Settings.Client,
		"requested_token_type": requestTokenType,
		"client_secret":        connection.Settings.ClientSecret,
	})

	if err != nil {
		return nil, err
	}
	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return nil, fmt.Errorf(parsed.Get("error").String())
	}
	var j JWT
	err = json.Unmarshal(result.Bytes(), &j)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// Sessions returns a list of sessions for the specified user.
func (connection *Connection) Sessions(u *UserInstance) ([]Session, error) {
	var sessions []Session
	var endpoint = "auth/admin"
	if connection.Settings.Version >= 18 {
		endpoint = "/admin"
	}
	var result, err = connection.Get(endpoint, "/users/"+u.UUID+"/sessions", curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	})
	if err != nil {
		return sessions, err
	}
	var parsed = gjson.Parse(result.String())
	if parsed.Get("error").String() != "" {
		return sessions, fmt.Errorf(parsed.Get("error").String())
	}
	err = json.Unmarshal(result.Bytes(), &sessions)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// LogoutSession logs out a session by making an HTTP DELETE request to the server.
// It takes a session object as a parameter and returns an error if any.
// The session ID is used to construct the URL for the logout request.
// The authorization header is set with the access token of the admin.
// If the response status code is 204, it means the logout was successful and nil error is returned.
// Otherwise, an error is returned indicating the failure to logout.
func (connection *Connection) LogoutSession(session *Session) error {
	var url = connection.Settings.Server + "/admin/realms/" + connection.Settings.Realm + "/sessions/" + session.ID
	resp, err := curl.Delete(url, curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, timeout)
	if err != nil {
		return err
	}
	if resp.Response().StatusCode == 204 {
		return nil
	}
	return fmt.Errorf("unable to logout")
}

// LogoutAllSessions logs out all sessions for the given user.
// It sends a POST request to the server's logout endpoint with the user's ID.
// The request is authenticated with the administrator's access token.
// If the request is successful and the server returns a 204 status code, nil error is returned.
// If the request fails or the server returns a different status code, an error is returned with the message "unable to logout".
func (connection *Connection) LogoutAllSessions(user *UserInstance) error {
	var url = connection.Settings.Server + "/admin/realms/" + connection.Settings.Realm + "/users/" + user.UUID + "/logout"
	resp, err := curl.Post(url, curl.Header{
		"Authorization": "Bearer " + connection.Admin.AccessToken,
	}, timeout)
	if err != nil {
		return err
	}
	if resp.Response().StatusCode == 204 {
		return nil
	}
	return fmt.Errorf("unable to logout")
}

// Connect establishes a connection using the provided settings.
// It returns a pointer to a Connection object and an error.
func Connect(s ...Settings) (*Connection, error) {
	var config Settings
	if len(s) == 0 {
		if conn != nil {
			return conn, nil
		}
		config = Settings{
			Server:       settings.Get("AUTH.KEYCLOAK.SERVER").String(),
			Realm:        settings.Get("AUTH.KEYCLOAK.REALM").String(),
			ClientSecret: settings.Get("AUTH.KEYCLOAK.SECRET").String(),
			Client:       settings.Get("AUTH.KEYCLOAK.CLIENT").String(),
			Debug:        settings.Get("AUTH.KEYCLOAK.DEBUG").Bool(),
			Version:      settings.Get("AUTH.KEYCLOAK.VERSION").Int(),
		}
	} else {
		config = s[0]
	}
	config.Server = strings.TrimRight(config.Server, "/") + "/"
	var connection = Connection{
		Settings: &config,
	}
	defer func() {
		if len(s) == 0 {
			conn = &connection
		}
	}()
	var auth = "/auth"
	if config.Version >= 18 {
		auth = ""
	}
	resp, err := curl.Get(fmt.Sprintf("%s%s/realms/%s/protocol/openid-connect/certs", strings.Trim(config.Server, "/"), auth, config.Realm), timeout)
	if err != nil {
		return &connection, err
	}
	if config.Debug {
		fmt.Println(resp.Dump())
	}
	connection.Certificate = jose.JSONWebKeySet{}
	err = resp.ToJSON(&connection.Certificate)

	if err != nil {
		log.Error(err)
		return &connection, err
	}

	j, err := connection.UpdateAdminToken(config.Realm)
	if err != nil {
		log.Error(err)
		return &connection, err
	}
	var claims map[string]interface{}
	token, err := connection.ParseToken(j.AccessToken, &claims, false)
	if err != nil {
		return nil, err
	}
	if token.Exp != nil && token.Iat != nil {
		go func() {
			for {
				expTime := time.Unix(int64(*token.Exp), 0).Add(-time.Minute)
				waitDuration := time.Until(expTime)
				now := time.Now()
				if now.After(expTime) {
					log.Error("keycloak admin token expiration time is too close or already passed.")
					waitDuration = 5 * time.Minute
				}
				time.Sleep(waitDuration)
				_, err = connection.UpdateAdminToken(config.Realm)
				if err != nil {
					log.Error(err)
				}
			}
		}()
	} else {
		return &connection, fmt.Errorf("invalid admin token")
	}
	return &connection, nil
}
