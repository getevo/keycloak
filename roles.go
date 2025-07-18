package keycloak

import (
	"fmt"
	"github.com/getevo/evo/v2/lib/curl"
	"github.com/getevo/evo/v2/lib/text"
	"github.com/tidwall/gjson"
)

type Role struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Composite   bool    `json:"composite"`
	ClientRole  bool    `json:"clientRole"`
	ContainerID string  `json:"containerId"`
	Error       *string `json:"errorMessage,omitempty"`
}

func (connection *Connection) GetRoles() ([]Role, error) {
	result, err := connection.Get("/admin", "/roles?first=0&max=9999")
	if err != nil {
		return nil, err
	}
	var roles []Role
	err = result.ToJSON(&roles)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func GetRoles() ([]Role, error) {
	return conn.GetRoles()
}

func (connection *Connection) GetRole(id string) (Role, error) {
	var role Role
	result, err := connection.Get("/admin", "/roles-by-id/"+id)
	if err != nil {
		return role, err
	}

	err = result.ToJSON(&role)
	if err != nil {
		return role, err
	}
	return role, nil
}

func GetRole(id string) (Role, error) {
	return conn.GetRole(id)
}

func (connection *Connection) CreateRole(name, description string) (Role, error) {
	var role Role
	if name == "" {
		return role, fmt.Errorf("name is required")
	}
	payload := map[string]interface{}{
		"name":        text.Slugify(name),
		"description": description,
		"composite":   false,
		"clientRole":  false,
	}
	result, err := connection.Post("/admin", "/roles", curl.BodyJSON(payload))
	if err != nil {
		return role, err
	}

	err = result.ToJSON(&role)
	if err != nil {
		return role, err
	}
	if role.Error != nil {
		return role, fmt.Errorf(*role.Error)
	}
	return role, nil
}

func CreateRole(name, description string) (Role, error) {
	return conn.CreateRole(name, description)
}

func (connection *Connection) UpdateRole(roleID, name, description string) (Role, error) {
	var role Role
	var err error
	if name == "" {
		return role, fmt.Errorf("name is required")
	}
	role, err = connection.GetRole(roleID)
	if err != nil {
		return role, err
	}

	role.Name = text.Slugify(name)
	role.Description = description
	result, err := connection.Put("/admin", "/roles-by-id/"+roleID, curl.BodyJSON(role))

	if err != nil {
		return role, err
	}
	if result.Response().StatusCode != 204 {
		return role, fmt.Errorf(gjson.Parse(result.String()).Get("errorMessage").String())
	}
	return role, nil
}

func UpdateRole(roleID, name, description string) (Role, error) {
	return conn.UpdateRole(roleID, name, description)
}

func (connection *Connection) DeleteRole(roleID string) error {
	_, err := connection.Delete("/admin", "/roles-by-id/"+roleID)
	return err
}

func DeleteRole(roleID string) error {
	return conn.DeleteRole(roleID)
}
