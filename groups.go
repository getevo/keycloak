package keycloak

import (
	"fmt"
	"github.com/getevo/evo/v2/lib/curl"
)

type Group struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Path          string        `json:"path"`
	SubGroupCount int           `json:"subGroupCount"`
	SubGroups     []interface{} `json:"subGroups"`
	Access        struct {
		View             bool `json:"view"`
		ViewMembers      bool `json:"viewMembers"`
		ManageMembers    bool `json:"manageMembers"`
		Manage           bool `json:"manage"`
		ManageMembership bool `json:"manageMembership"`
	} `json:"access"`
	RealmRoles []string `json:"realmRoles"`
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
	result, err := connection.Post("/admin", "/groups", curl.BodyJSON(group))
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
	group.ID = createdGroup.ID
	group.Path = createdGroup.Path
	return nil
}

func CreateGroup(group *Group) error {
	return conn.CreateGroup(group)
}

func (connection *Connection) UpdateGroup(group *Group) error {
	result, err := connection.Put("/admin", "/groups/"+group.ID, curl.BodyJSON(group))
	if err != nil {
		return err
	}
	var updatedGroup Group
	err = result.ToJSON(&updatedGroup)
	if err != nil {
		return err
	}
	if updatedGroup.ID != group.ID {
		return fmt.Errorf("expected group ID %s, got %s", group.ID, updatedGroup.ID)
	}
	group.ID = updatedGroup.ID
	group.Path = updatedGroup.Path
	return nil
}

func UpdateGroup(group *Group) error {
	return conn.UpdateGroup(group)
}

func (connection *Connection) DeleteGroup(id string) error {
	_, err := connection.Delete("/admin", "/groups/"+id)
	return err
}

func DeleteGroup(id string) error {
	return conn.DeleteGroup(id)
}
