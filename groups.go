package keycloak

import (
	"fmt"
	"github.com/getevo/evo/v2/lib/curl"
	"github.com/tidwall/gjson"
)

type Group struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Path          string        `json:"path"`
	SubGroupCount int           `json:"subGroupCount,omitempty"`
	SubGroups     []interface{} `json:"subGroups,omitempty"`
	Access        struct {
		View             bool `json:"view"`
		ViewMembers      bool `json:"viewMembers"`
		ManageMembers    bool `json:"manageMembers"`
		Manage           bool `json:"manage"`
		ManageMembership bool `json:"manageMembership"`
	} `json:"access,omitempty"`
	RealmRoles []string `json:"realmRoles,omitempty"`
	Error      *string  `json:"errorMessage,omitempty"`
}

func (connection *Connection) GetGroups() ([]Group, error) {
	result, err := connection.Get("/admin", "/groups?first=0&max=9999")
	if err != nil {
		return nil, err
	}
	var groups []Group
	err = result.ToJSON(&groups)
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func GetGroups() ([]Group, error) {
	return conn.GetGroups()
}

func (connection *Connection) GetGroup(id string) (*Group, error) {
	result, err := connection.Get("/admin", "/groups/"+id)
	if err != nil {
		return nil, err
	}
	var group Group
	err = result.ToJSON(&group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func GetGroup(id string) (*Group, error) {
	return conn.GetGroup(id)
}

func (connection *Connection) CreateGroup(group *Group) error {
	//var roles = group.RealmRoles
	var payload = map[string]interface{}{
		"name": group.Name,
	}
	result, err := connection.Post("/admin", "/groups", curl.BodyJSON(payload))
	if err != nil {
		return err
	}
	var createdGroup Group
	err = result.ToJSON(&createdGroup)
	if err != nil {
		return err
	}
	if createdGroup.Error != nil {
		return fmt.Errorf(*createdGroup.Error)
	}
	if createdGroup.ID == "" {
		return fmt.Errorf("expected group ID, got empty string")
	}
	group.ID = createdGroup.ID
	group.Path = createdGroup.Path
	err = connection.UpdateGroup(group.ID, group)
	if err != nil {
		return err
	}
	return nil
}

func CreateGroup(group *Group) error {
	return conn.CreateGroup(group)
}

func (connection *Connection) UpdateGroup(id string, group *Group) error {
	group.ID = id
	// rename the group if necessary
	if group.Name != "" {
		var payload = map[string]interface{}{
			"name": group.Name,
		}
		result, err := connection.Put("/admin", "/groups/"+group.ID, curl.BodyJSON(payload))
		if err != nil {
			return fmt.Errorf("unable to update group name: %w", err)
		}

		if result.Response().StatusCode != 204 {
			return fmt.Errorf(gjson.Parse(result.String()).Get("errorMessage").String())
		}

	}

	roles, err := connection.GetRoles()
	if err != nil {
		return fmt.Errorf("unable to retrieve roles: %w", err)
	}
	// update the group roles
	var payload []Role
	for _, role := range group.RealmRoles {
		for idx, roleMapping := range roles {
			if roleMapping.Name == role || roleMapping.ID == role {
				payload = append(payload, roles[idx])
				break
			}
		}
	}

	result, err := connection.Post("/admin", "/groups/"+group.ID+"/role-mappings/realm", curl.BodyJSON(payload))
	fmt.Println(result.Dump())
	if err != nil {
		return err
	}

	return nil
}

func UpdateGroup(id string, group *Group) error {
	return conn.UpdateGroup(id, group)
}

func (connection *Connection) DeleteGroup(id string) error {
	_, err := connection.Delete("/admin", "/groups/"+id)
	return err
}

func DeleteGroup(id string) error {
	return conn.DeleteGroup(id)
}
