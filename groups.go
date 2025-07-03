package keycloak

import (
	"fmt"
	"github.com/getevo/evo/v2/lib/curl"
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
	if createdGroup.ID == "" {
		return fmt.Errorf("expected group ID, got empty string")
	}
	err = connection.UpdateGroup(group.ID, group)
	if err != nil {
		return err
	}
	group.ID = createdGroup.ID
	group.Path = createdGroup.Path
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
		fmt.Println(result.Dump())
		if err == nil {
			return fmt.Errorf("group with name %s already exists", group.Name)
		}

	}

	// update the group roles
	var payload = []map[string]interface{}{}
	for _, role := range group.RealmRoles {
		payload = append(payload, map[string]interface{}{
			"name": role,
		})
	}

	result, err := connection.Put("/admin", "/groups/"+group.ID+"/role-mappings/realm", curl.BodyJSON(payload))
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
