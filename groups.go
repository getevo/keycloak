package keycloak

import (
	"fmt"
	"github.com/getevo/evo/v2/lib/curl"
	"github.com/getevo/evo/v2/lib/text"
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
	if group.Name == "" {
		return fmt.Errorf("expected non-empty group name")
	}
	var payload = map[string]interface{}{
		"name": text.Slugify(group.Name),
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
			"name": text.Slugify(group.Name),
		}
		result, err := connection.Put("/admin", "/groups/"+group.ID, curl.BodyJSON(payload))
		if err != nil {
			return fmt.Errorf("unable to update group name: %w", err)
		}

		if result.Response().StatusCode != 204 {
			return fmt.Errorf(gjson.Parse(result.String()).Get("errorMessage").String())
		}

	}
	err := connection.SetGroupRoles(id, group)
	if err != nil {
		return fmt.Errorf("unable to update group roles: %w", err)
	}
	return nil
}

func UpdateGroup(id string, group *Group) error {
	return conn.UpdateGroup(id, group)
}

func (connection *Connection) SetGroupRoles(id string, group *Group) error {
	// Get all available roles
	allRoles, err := connection.GetRoles()
	if err != nil {
		return fmt.Errorf("unable to retrieve roles: %w", err)
	}

	// Get current group to see existing roles
	currentGroup, err := connection.GetGroup(id)
	if err != nil {
		return fmt.Errorf("unable to get current group: %w", err)
	}

	// Create maps for easier lookup
	roleMap := make(map[string]Role)
	for _, role := range allRoles {
		roleMap[role.Name] = role
		roleMap[role.ID] = role
	}

	// Build list of desired roles, validating they exist
	var desiredRoles []Role
	desiredRoleNames := make(map[string]bool)
	for _, roleName := range group.RealmRoles {
		role, exists := roleMap[roleName]
		if !exists {
			return fmt.Errorf("role %s not found", roleName)
		}
		desiredRoles = append(desiredRoles, role)
		desiredRoleNames[role.Name] = true
	}

	// Build list of current roles
	currentRoleNames := make(map[string]bool)
	for _, roleName := range currentGroup.RealmRoles {
		currentRoleNames[roleName] = true
	}

	// Determine roles to add (in desired but not in current)
	var rolesToAdd []Role
	for _, role := range desiredRoles {
		if !currentRoleNames[role.Name] {
			rolesToAdd = append(rolesToAdd, role)
		}
	}

	// Determine roles to remove (in current but not in desired)
	var rolesToRemove []Role
	for _, roleName := range currentGroup.RealmRoles {
		if !desiredRoleNames[roleName] {
			if role, exists := roleMap[roleName]; exists {
				rolesToRemove = append(rolesToRemove, role)
			}
		}
	}

	// Add new roles
	if len(rolesToAdd) > 0 {
		result, err := connection.Post("/admin", "/groups/"+id+"/role-mappings/realm", curl.BodyJSON(rolesToAdd))
		if err != nil {
			return fmt.Errorf("unable to add roles: %w", err)
		}
		if result.Response().StatusCode != 204 {
			return fmt.Errorf("failed to add roles: %s", gjson.Parse(result.String()).Get("errorMessage").String())
		}
	}

	// Remove old roles
	if len(rolesToRemove) > 0 {
		result, err := connection.Delete("/admin", "/groups/"+id+"/role-mappings/realm", curl.BodyJSON(rolesToRemove))
		if err != nil {
			return fmt.Errorf("unable to remove roles: %w", err)
		}
		if result.Response().StatusCode != 204 {
			return fmt.Errorf("failed to remove roles: %s", gjson.Parse(result.String()).Get("errorMessage").String())
		}
	}

	return nil
}

func SetGroupRoles(id string, group *Group) error {
	return conn.SetGroupRoles(id, group)
}

func (connection *Connection) DeleteGroup(id string) error {
	_, err := connection.Delete("/admin", "/groups/"+id)
	return err
}

func DeleteGroup(id string) error {
	return conn.DeleteGroup(id)
}

func (connection *Connection) SetUserGroups(uuid string, groups []string) error {
	// 1- get user groups
	userGroups, err := connection.GetUserGroups(uuid)
	if err != nil {
		return fmt.Errorf("failed to get user groups: %w", err)
	}

	// 2- join to new groups
	for _, groupID := range groups {
		var found = false
		for _, item := range userGroups {
			if item.ID == groupID {
				found = true
				break
			}
		}
		if !found {
			err := connection.UserJoinGroup(uuid, groupID)
			if err != nil {
				return fmt.Errorf("failed to join group %s: %w", groupID, err)
			}
		}
	}

	// 3- remove from removed groups
	for _, item := range userGroups {
		var found = false
		for _, groupID := range groups {
			if item.ID == groupID {
				found = true
				break
			}
		}
		if !found {
			err := connection.UserLeaveGroup(uuid, item.ID)
			if err != nil {
				return fmt.Errorf("failed to leave group %s: %w", item.ID, err)
			}
		}
	}

	return nil
}

func SetUserGroups(uuid string, groups []string) error {
	return conn.SetUserGroups(uuid, groups)
}

func (connection *Connection) GetUserGroups(uuid string) ([]Group, error) {
	result, err := connection.Get("/admin", "/users/"+uuid+"/groups?first=0&max=99999")
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

func GetUserGroups(uuid string) ([]Group, error) {
	return conn.GetUserGroups(uuid)
}

func (connection *Connection) UserJoinGroup(uuid, groupID string) error {
	result, err := connection.Put("/admin", "/users/"+uuid+"/groups/"+groupID, nil)
	if err != nil {
		return err
	}
	if result.Response().StatusCode != 204 {
		return fmt.Errorf(gjson.Parse(result.String()).Get("errorMessage").String())
	}
	return nil
}

func UserJoinGroup(uuid, groupID string) error {
	return conn.UserJoinGroup(uuid, groupID)
}

func (connection *Connection) UserLeaveGroup(uuid, groupID string) error {
	result, err := connection.Delete("/admin", "/users/"+uuid+"/groups/"+groupID, nil)
	if err != nil {
		return err
	}
	if result.Response().StatusCode != 204 {
		return fmt.Errorf(gjson.Parse(result.String()).Get("errorMessage").String())
	}
	return nil
}

func UserLeaveGroup(uuid, groupID string) error {
	return conn.UserLeaveGroup(uuid, groupID)
}
