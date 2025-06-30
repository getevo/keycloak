package keycloak

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/getevo/evo/v2"
	"github.com/getevo/evo/v2/lib/curl"
	"github.com/getevo/evo/v2/lib/date"
	"github.com/getevo/evo/v2/lib/generic"
	"github.com/go-jose/go-jose/v4"
	"net/http"
	"strconv"
	"time"
)

// JWT represents a JSON Web Token. It contains various fields used for token-based authentication and authorization.
// AccessToken is the access token issued by the server.
// It is used to authenticate the client when making requests.
// It is a required field in the JWT.
type JWT struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// Connection represents a connection to a server with authentication settings.
type Connection struct {
	Settings *Settings
	Admin    *JWT
	//Certificate jose.JSONWebKeySet
	Certificate jose.JSONWebKeySet
}

func (connection *Connection) PrepareRequest(data []interface{}) []interface{} {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	var c = &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	data = append(data, c)
	if connection.Admin == nil {
		return data
	}
	var hasHeader = false
	for idx, _ := range data {
		if headers, ok := data[idx].(curl.Header); ok {
			hasHeader = true
			if _, ok := headers["Authorization"]; !ok {
				headers["Authorization"] = "Bearer " + connection.Admin.AccessToken
			}
		}
	}
	if !hasHeader {
		data = append(data, curl.Header{"Authorization": "Bearer " + connection.Admin.AccessToken})
	}
	return data
}

// Settings represents the configuration settings for connecting to a server in the application. It contains fields for the server URL, realm, client, client secret, autoconnect flag
type Settings struct {
	Server       string `json:"server"`
	Realm        string `json:"realm"`
	Client       string `json:"client"`
	ClientSecret string `json:"client_secret"`
	BasePath     string `json:"basepath"`
	Debug        bool   `json:"debug"`
}

// UserAddress represents a user's address information.
// It has the following fields:
// - Formatted: the formatted address as a single string
// - StreetAddress: the street address
// - Locality: the city or locality
// - Region: the region or state
// - PostalCode: the postal code or ZIP code
// - Country: the country
// The fields are optional and may be empty.
//
// This type is defined according to the Address Claim in the OpenID Connect Core specification.
// For more information, refer to: https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
type UserAddress struct {
	Formatted     *string `json:"formatted,omitempty"`
	StreetAddress *string `json:"street_address,omitempty"`
	Locality      *string `json:"locality,omitempty"`
	Region        *string `json:"region,omitempty"`
	PostalCode    *string `json:"postal_code,omitempty"`
	Country       *string `json:"country,omitempty"`
}

type UserInstance struct {
	UUID             string               `json:"id" form:"id"`
	Username         string               `json:"username" form:"username"`
	FirstName        string               `json:"firstName" form:"firstName"`
	LastName         string               `json:"lastName" form:"lastName"`
	Email            string               `json:"email" form:"email"`
	CreatedAt        int64                `json:"createdTimestamp"`
	RegistrationDate time.Time            `json:"-"`
	IsAdmin          bool                 `json:"-" form:"is_admin"`
	EmailVerified    bool                 `json:"emailVerified"`
	Enabled          bool                 `json:"enabled" form:"enabled"`
	Attributes       Attributes           `json:"attributes"`
	Credentials      *[]Credentials       `json:"credentials,omitempty"`
	RequiredActions  *[]string            `json:"requiredActions,omitempty"`
	Access           *map[string]bool     `json:"access,omitempty"`
	ClientRoles      *map[string][]string `json:"clientRoles,omitempty"`
	RealmRoles       *[]string            `json:"realmRoles,omitempty"`
	Groups           *[]string            `json:"groups,omitempty"`
	FederationLink   *string              `json:"federationLink,omitempty"`
	Totp             *bool                `json:"totp,omitempty"`
}

// Credentials is a type that represents user credentials, such as passwords or access tokens.
// It contains the following fields:
//   - Type: string, specifies the type of the credential, e.g., "password" or "token".
//   - Value: string, holds the actual value of the credential.
//   - Temporary: bool, indicates whether the credential is temporary or not.
//
// This type is used in the `User` struct to store user credentials.
type Credentials struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// Attributes represents a map of attribute names to slices of values. Each attribute can have multiple values.
type Attributes map[string][]string

// Value is a type that represents a generic value.
type Value struct {
	Object interface{}
}

// Set sets the value of the specified key in the Attributes map
// Parameters:
//   - key: the key to set
//   - value: the value to set for the key
func (attribs *Attributes) Set(key string, value string) {
	(*attribs)[key] = []string{value}
}

func (attribs Attributes) Get(key string) Value {
	if v, ok := attribs[key]; ok {
		if len(v) > 0 {
			return Value{v[0]}
		}
	}
	return Value{""}
}

func (v Value) String() string {
	return fmt.Sprint(v.Object)
}

func (v Value) Int() int {
	res, _ := strconv.Atoi(v.String())
	return res
}

// Int64 returns the value of the Value object as an int64. If the conversion fails, it returns 0.
func (v Value) Int64() int64 {
	res, _ := strconv.ParseInt(v.String(), 10, 64)
	return res
}

// Uint converts the string representation of the Value to an unsigned integer of type uint64. If the conversion fails, it returns zero.
func (v Value) Uint() uint64 {
	res, _ := strconv.ParseInt(v.String(), 10, 64)
	return uint64(res)
}

// Time returns a time.Time value by parsing the Object field of the Value struct as a string using the date.Parse function.
// It returns an error if the parsing fails.
func (v Value) Time() (time.Time, error) {
	dt, err := date.Parse(fmt.Sprint(v.Object))
	return dt.Base, err
}

type Reset struct {
	IDUser    string    `gorm:"column:uuid"`
	OTP       string    `gorm:"column:otp"`
	CreatedAt time.Time `gorm:"column:created_at"`
	Used      bool      `gorm:"column:used"`
}

// TableName returns the name of the table associated with the Reset model in the database.
func (Reset) TableName() string {
	return "reset"
}

type Spec struct {
	Permissions *[]ResourcePermission `json:"permissions,omitempty"`
	Exp         *int                  `json:"exp,omitempty"`
	Nbf         *int                  `json:"nbf,omitempty"`
	Iat         *int                  `json:"iat,omitempty"`
	Aud         *StringOrArray        `json:"aud,omitempty"`
	Active      *bool                 `json:"active,omitempty"`
	AuthTime    int                   `json:"auth_time,omitempty"`
	Jti         *string               `json:"jti,omitempty"`
	Type        *string               `json:"typ,omitempty"`
}

// StringOrArray is a type that represents a string or an array of strings.
// It is commonly used to handle JSON values that can be either a single string or an array of strings.
// This type provides methods to unmarshal and marshal JSON data to/from the StringOrArray type.
// UnmarshalJSON is a method that implements the json.Unmarshaler interface for the StringOrArray type.
// It parses a JSON value and sets the value of the StringOrArray variable accordingly.
// If the JSON value is an array of strings, it will be assigned directly to the StringOrArray variable.
// If the JSON value is a single string, it will be converted to a StringOrArray variable with one element.
// If there is an error during unmarshaling, it will be returned.
// MarshalJSON is a method that implements the json.Marshaler interface for the StringOrArray type.
// It converts the value of the StringOrArray variable to its JSON representation.
// If the StringOrArray variable contains only one string, it will be marshaled as a single string.
// If the StringOrArray variable contains multiple strings, it will be marshaled as an array of strings.
// If there is an error during marshaling, it will be returned.
// Example usage:
// ```
//
//	Spec struct {
//	    Permissions *[]ResourcePermission `json:"permissions,omitempty"`
//	    Exp         *int                  `json:"exp,omitempty"`
//	    Nbf         *int                  `json:"nbf,omitempty"`
//	    Iat         *int                  `json:"iat,omitempty"`
//	    Aud         *StringOrArray        `json:"aud,omitempty"`
//	    Active      *bool                 `json:"active,omitempty"`
//	    AuthTime    int                   `json:"auth_time,omitempty"`
//	    Jti         *string               `json:"jti,omitempty"`
//	    Type        *string               `json:"typ,omitempty"`
//	}
//
// ```
// Example usage:
// ```
//
//	func (s *StringOrArray) UnmarshalJSON(data []byte) error {
//	    if len(data) > 1 && data[0] == '[' {
//	        var obj []string
//	        if err := json.Unmarshal(data, &obj); err != nil {
//	            return err
//	        }
//	        *s = StringOrArray(obj)
//	        return nil
//	    }
//	    var obj string
//	    if err := json.Unmarshal(data, &obj); err != nil {
//	        return err
//	    }
//	    *s = StringOrArray([]string{obj})
//	    return nil
//	}
//
// ```
// Example usage:
// ```
//
//	func (s *StringOrArray) MarshalJSON() ([]byte, error) {
//	    if len(*s) == 1 {
//	        return json.Marshal([]string(*s)[0])
//	    }
//	    return json.Marshal([]string(*s))
//	}
//
// ```
type StringOrArray []string

// UnmarshalJSON parses the JSON data and converts it to a StringOrArray.
// If the JSON data is an array of strings, it assigns it to the StringOrArray.
// If the JSON data is a single string, it assigns it as the only element of the StringOrArray.
func (s *StringOrArray) UnmarshalJSON(data []byte) error {
	if len(data) > 1 && data[0] == '[' {
		var obj []string
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		*s = StringOrArray(obj)
		return nil
	}

	var obj string
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*s = StringOrArray([]string{obj})
	return nil
}

// MarshalJSON marshals a string or an array object to a valid JSON representation.
// If the length of the StringOrArray is 1, it marshals the single element as a JSON string.
// Otherwise, it marshals the entire StringOrArray as a JSON array of strings.
// It returns the marshaled JSON bytes and any error encountered during marshaling.
func (s *StringOrArray) MarshalJSON() ([]byte, error) {
	if len(*s) == 1 {
		return json.Marshal([]string(*s)[0])
	}
	return json.Marshal([]string(*s))
}

// ResourcePermission represents the permission for a specific resource
//
// Fields:
// - RSID: The unique identifier of the resource server
// - ResourceID: The unique identifier of the resource
// - RSName: The name of the resource server
// - Scopes: The scopes associated with the permission
// - ResourceScopes: The scopes specific to the resource
type ResourcePermission struct {
	RSID           *string   `json:"rsid,omitempty"`
	ResourceID     *string   `json:"resource_id,omitempty"`
	RSName         *string   `json:"rsname,omitempty"`
	Scopes         *[]string `json:"scopes,omitempty"`
	ResourceScopes *[]string `json:"resource_scopes,omitempty"`
}

// implementation
type Session struct {
	Clients    map[string]string `json:"clients,omitempty"`
	ID         string            `json:"id,omitempty"`
	IPAddress  string            `json:"ipAddress,omitempty"`
	LastAccess int64             `json:"lastAccess,omitempty"`
	Start      int64             `json:"start,omitempty"`
	UserID     string            `json:"userId,omitempty"`
	Username   string            `json:"username,omitempty"`
	connection *Connection
}

// Logout logs out the current session by calling the LogoutSession method
func (session *Session) Logout() error {
	return session.connection.LogoutSession(session)
}

// Logout logs out the user from all sessions.
// It calls the LogoutAllSessions method of the user's connection.
// The user's connection is set when the user is created.
// If an error occurs during the logout process, it is returned.
func (user *UserInstance) Logout() error {
	return conn.LogoutAllSessions(user)
}

func (keycloakUser *UserInstance) SetFromStruct(user evo.UserInterface) {
	if keycloakUser.Username == "" {
		keycloakUser.FirstName = user.GetFirstName()
		keycloakUser.LastName = user.GetLastName()
		keycloakUser.Username = user.GetEmail()
		keycloakUser.Email = user.GetEmail()
	}
	var g = generic.Parse(user)
	if keycloakUser.Attributes == nil {
		keycloakUser.Attributes = map[string][]string{}
	}
	for _, v := range g.Props() {
		var t = v.Tag.Get("profile")
		if t == "" || t == "-" {
			continue
		}
		var value = g.Prop(v.Name)
		if !value.IsNil() {
			keycloakUser.Attributes.Set(v.Tag.Get("json"), value.String())
		}

	}
}

type User struct {
	UUID          string `keycloak:"field:UUID" gorm:"column:uuid;primaryKey;size:36" json:"uuid"`
	FirstName     string `keycloak:"field:FirstName" gorm:"column:first_name;size:255" validation:"name,required" json:"first_name"`
	LastName      string `keycloak:"field:LastName" gorm:"column:last_name;size:255" validation:"name,required" json:"last_name"`
	Email         string `keycloak:"field:Email" gorm:"column:email;size:255;unique" validation:"email,unique" json:"email"`
	Password      string `keycloak:"field:Password" gorm:"-" json:"password"`
	EmailVerified bool   `keycloak:"field:EmailVerified" gorm:"column:email_verified" json:"email_verified"`
	Enabled       bool   `keycloak:"field:Enabled" gorm:"column:enabled" json:"enabled"`
}

// Client represents the main client structure.
type Client struct {
	ID                                 string            `json:"id"`
	ClientID                           string            `json:"clientId"`
	Name                               string            `json:"name"`
	RootURL                            string            `json:"rootUrl,omitempty"`
	BaseURL                            string            `json:"baseUrl,omitempty"`
	SurrogateAuthRequired              bool              `json:"surrogateAuthRequired"`
	Enabled                            bool              `json:"enabled"`
	AlwaysDisplayInConsole             bool              `json:"alwaysDisplayInConsole"`
	ClientAuthenticatorType            string            `json:"clientAuthenticatorType"`
	Secret                             string            `json:"secret,omitempty"`
	RedirectURIs                       []string          `json:"redirectUris"`
	WebOrigins                         []string          `json:"webOrigins"`
	NotBefore                          int               `json:"notBefore"`
	BearerOnly                         bool              `json:"bearerOnly"`
	ConsentRequired                    bool              `json:"consentRequired"`
	StandardFlowEnabled                bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled                bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled          bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled             bool              `json:"serviceAccountsEnabled"`
	AuthorizationServicesEnabled       bool              `json:"authorizationServicesEnabled,omitempty"`
	PublicClient                       bool              `json:"publicClient"`
	Protocol                           string            `json:"protocol"`
	Attributes                         map[string]string `json:"attributes"`
	AuthenticationFlowBindingOverrides map[string]string `json:"authenticationFlowBindingOverrides"`
	FullScopeAllowed                   bool              `json:"fullScopeAllowed"`
	NodeReRegistrationTimeout          int               `json:"nodeReRegistrationTimeout"`
	ProtocolMappers                    []ProtocolMapper  `json:"protocolMappers,omitempty"`
	DefaultClientScopes                []string          `json:"defaultClientScopes"`
	OptionalClientScopes               []string          `json:"optionalClientScopes"`
	Access                             Access            `json:"access"`
}

// ProtocolMapper represents the protocol mapper structure.
type ProtocolMapper struct {
	ID              *string           `json:"id,omitempty"`
	Name            string            `json:"name"`
	Protocol        string            `json:"protocol"`
	ProtocolMapper  string            `json:"protocolMapper"`
	ConsentRequired bool              `json:"consentRequired"`
	Config          map[string]string `json:"config"`
}

// Access represents the access permissions for a client.
type Access struct {
	View      bool `json:"view"`
	Configure bool `json:"configure"`
	Manage    bool `json:"manage"`
}
