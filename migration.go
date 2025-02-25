package keycloak

import (
	"github.com/getevo/evo/v2/lib/curl"
	"github.com/getevo/evo/v2/lib/db/schema"
	"github.com/getevo/evo/v2/lib/log"
	"reflect"
	"strings"
)

func migrate() {
	var t = reflect.TypeOf(User{})
	for i, _ := range schema.Models {
		var model = schema.Models[i]
		for idx := range model.Type.NumField() {
			field := model.Type.Field(idx)
			if field.Type == t {
				userModel = &model
				MigrateFields(userModel)
				break
			}
		}

	}
}

func MigrateFields(model *schema.Model) {
	log.Info("Migrating keycloak fields for model:", model.Name)
	for _, field := range model.Schema.Fields {
		var tag = field.Tag.Get("keycloak")
		var chunks = strings.Split(tag, ":")
		if len(chunks) == 2 {
			var op = chunks[0]
			var name = chunks[1]
			var _type = "String"
			var fieldType = field.FieldType
			for fieldType.Kind() == reflect.Ptr {
				fieldType = fieldType.Elem()
			}
			switch fieldType.Kind() {
			case
				reflect.Int8, reflect.Int64, reflect.Int,
				reflect.Int32, reflect.Int16, reflect.Float32, reflect.Float64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				_type = "int"
			case reflect.Bool:
				_type = "boolean"
			case reflect.Struct, reflect.Slice, reflect.Map:
				_type = "JSON"
			default:
				_type = "String"
			}

			if op == "attribute" {
				var found = false
				for _, item := range client.ProtocolMappers {
					if item.ProtocolMapper == "oidc-usermodel-attribute-mapper" {
						if v, ok := item.Config["user.attribute"]; ok && v == name {
							found = true
							break
						}
					}
				}

				if !found {
					var endpoint = "auth/admin"
					if conn.Settings.Version >= 18 {
						endpoint = "admin"
					}
					conn.Post(endpoint, "/clients/"+client.ID+"/protocol-mappers/models/", curl.Header{
						"Authorization": "Bearer " + conn.Admin.AccessToken,
					}, curl.BodyJSON(ProtocolMapper{
						Protocol:       "openid-connect",
						ProtocolMapper: "oidc-usermodel-attribute-mapper",
						Name:           name,
						Config: map[string]string{
							"claim.name":                name,
							"jsonType.label":            _type,
							"id.token.claim":            "true",
							"access.token.claim":        "true",
							"lightweight.claim":         "true",
							"userinfo.token.claim":      "true",
							"introspection.token.claim": "true",
							"user.attribute":            name,
						},
					}))

				}
			}

		}
	}
}
