package keycloak

import (
	"fmt"
	"github.com/getevo/evo/v2/lib/db/schema"
	"github.com/getevo/evo/v2/lib/text"
	"reflect"
	"strings"
)

func (connection *Connection) EditUserFromStruct(user interface{}) error {
	var _typ = reflect.TypeOf(user)
	if _typ.Kind() != reflect.Ptr {
		return fmt.Errorf("user must be a pointer")
	}
	_, err := getUserModel(_typ)
	if err != nil {
		return err
	}
	var keycloakUser = UserInstance{
		Attributes: map[string][]string{},
	}

	var uuid = getUUID(user)
	keycloakUser, err = connection.GetUser(uuid)
	if err != nil {
		return err
	}

	err, _ = setFieldValues(user, &keycloakUser)

	if err != nil {
		return err
	}
	if keycloakUser.Credentials != nil && len(*keycloakUser.Credentials) > 0 && (*keycloakUser.Credentials)[0].Value != "" {
		err = connection.SetCredentials(&keycloakUser, (*keycloakUser.Credentials)[0])
		if err != nil {
			return err
		}
	}
	err = connection.EditUser(&keycloakUser)
	if err != nil {
		return err
	}
	return nil
}

func getUUID(user interface{}) string {
	var ref = reflect.ValueOf(user)
	for ref.Kind() == reflect.Ptr {
		ref = ref.Elem()
	}
	for _, field := range userModel.Schema.Fields {
		if field.Name == "UUID" {
			return sprint(ref.FieldByName(field.Name))
		}
		var chunks = strings.Split(field.Tag.Get("keycloak"), ":")
		if len(chunks) == 2 && chunks[0] == "field" && chunks[1] == "UUID" {
			return sprint(ref.FieldByName(field.Name))
		}
	}
	return ""
}

func setFieldValues(user interface{}, keycloakUser *UserInstance) (error, string) {
	var uuidField string
	var keycloakRef = reflect.ValueOf(keycloakUser)
	for keycloakRef.Kind() == reflect.Ptr {
		keycloakRef = keycloakRef.Elem()
	}
	var userRef = reflect.ValueOf(user)
	for userRef.Kind() == reflect.Ptr {
		userRef = userRef.Elem()
	}
	for _, field := range userModel.Schema.Fields {
		r := userRef.FieldByName(field.Name)
		f := keycloakRef.FieldByName(field.Name)
		if field.Name == "UUID" {
			uuidField = field.Name
			continue
		}

		if f.IsValid() && field.FieldType == f.Type() && !r.IsZero() {
			f.Set(reflect.ValueOf(r.Interface()))
			continue
		}

		var tag = field.Tag.Get("keycloak")
		var chunks = strings.Split(tag, ":")
		if len(chunks) != 2 {
			continue
		}
		if chunks[0] == "field" {
			if chunks[1] == "UUID" {
				uuidField = field.Name
				continue
			}
			if chunks[1] == "Password" {
				var value = sprint(r)
				if value != "" {
					keycloakUser.Credentials = &[]Credentials{
						{
							Type:      "password",
							Value:     value,
							Temporary: false,
						},
					}
				}
				continue
			}
			f = keycloakRef.FieldByName(chunks[1])

			if f.IsValid() && field.FieldType == f.Type() {
				if r.IsValid() && !r.IsZero() {
					f.Set(reflect.ValueOf(r.Interface()))
					break
				}
			} else {
				return fmt.Errorf("field %s not found or type missmatch in user model %s", chunks[1], userRef.Type().String()), uuidField
			}
		}
		if keycloakUser.Attributes == nil {
			keycloakUser.Attributes = Attributes{}
		}
		if chunks[0] == "attribute" {
			//r = userRef.FieldByName(field.Name)
			if !r.IsValid() || r.IsZero() || (r.Kind() == reflect.Ptr && r.IsNil()) || r.Interface() == nil {
				keycloakUser.Attributes.Set(chunks[1], "")
				continue
			}
			keycloakUser.Attributes.Set(chunks[1], sprint(r))
			continue
		}

	}
	if keycloakUser.Username == "" {
		keycloakUser.Username = keycloakUser.Email
	}

	return nil, uuidField
}

func getUserModel(_typ reflect.Type) (*schema.Model, error) {
	if userModel == nil {
		for idx, _ := range schema.Models {
			if schema.Models[idx].Name == _typ.Elem().String() {
				userModel = &schema.Models[idx]
				break
			}
		}
		if userModel == nil {
			return nil, fmt.Errorf("user model %s not found", _typ.String())
		}
	}
	return userModel, nil
}

func (connection *Connection) NewUserFromStruct(user interface{}) error {
	var _typ = reflect.TypeOf(user)
	if _typ.Kind() != reflect.Ptr {
		return fmt.Errorf("user must be a pointer")
	}

	_, err := getUserModel(_typ)
	if err != nil {
		return err
	}
	var keycloakUser = &UserInstance{
		Attributes: map[string][]string{},
	}

	var uuidField string
	err, uuidField = setFieldValues(user, keycloakUser)
	if err != nil {
		return err
	}
	err = connection.CreateUser(keycloakUser)
	if err != nil {
		return err
	}

	if uuidField != "" {
		reflect.ValueOf(user).Elem().FieldByName(uuidField).Set(reflect.ValueOf(keycloakUser.UUID))
	}

	return nil
}

func NewUser(user interface{}) error {
	return conn.NewUserFromStruct(user)
}

func EditUser(user interface{}) error {
	return conn.EditUserFromStruct(user)
}

func DeleteUser(uuid string) error {
	return conn.DeleteUser(uuid)
}

func Login(username, password string) (*JWT, error) {
	return conn.Login(username, password)
}

func RefreshToken(refreshToken string) (*JWT, error) {
	return conn.RefreshToken(refreshToken)
}

func GetUser(uuid string) (UserInstance, error) {
	return conn.GetUser(uuid)
}

func ParseToken(accessToken string, claims interface{}, strict bool) (Spec, error) {
	return conn.ParseToken(accessToken, claims, strict)
}

func LogoutSession(session *Session) error {
	return conn.LogoutSession(session)
}

func ChangePassword(user *UserInstance, password string) error {
	return conn.ChangePassword(user, password)
}

func VerifyOffline(accessToken string, claims interface{}) (Spec, error) {
	return conn.VerifyOffline(accessToken, claims)
}

func sprint(v reflect.Value) string {
	if !v.IsValid() || v.IsZero() {
		return ""
	}
	var result string
	switch v.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice:
		result = text.ToJSON(v)
	case reflect.Ptr:
		result = sprint(v.Elem())
	default:
		result = fmt.Sprint(v.Interface())
	}
	return result
}
