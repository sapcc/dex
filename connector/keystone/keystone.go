// Package keystone provides authentication strategy using Keystone.
package keystone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
	"github.com/gophercloud/utils/openstack/clientconfig"
)

const (
	DefaultDomain          string = "default"
	DefaultPrompt          string = "Username"
	DefaultGroupNameFormat string = "openstack_group:%s"
	DefaultRoleNameFormat  string = "openstack_role:%s"
)

type scope struct {
	ProjectID   string `json:"projectID,omitempty"`
	ProjectName string `json:"projectName,omitempty"`
	DomainID    string `json:"domainID,omitempty"`
	DomainName  string `json:"domainName,omitempty"`
}

type token struct {
	UserID    string   `json:"userID,omitempty"`
	ProjectID string   `json:"projectID,omitempty"`
	DomainID  string   `json:"domainID,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

type conn struct {
	ProviderClient *gophercloud.ProviderClient
	ServiceClient  *gophercloud.ServiceClient
	Logger         log.Logger
	Config         *Config
}

// Config holds the configuration parameters for Keystone connector.
// Keystone should expose API v3.
// A service account (adminUsername) with privileges to retrieve users, groups and role-assignments
// needs to be configured (permissions can be scoped with adminProject/adminDomain).
// If desired, a user roles can be included into the groups claim. Set "includeRolesInGroups" and specify an
// authScope (keystone domain and/or project) which will be applied to the user auth requests to evaluate the users roles.
// The groups claim entries can be namespaced by specifying a roleNameFormat and groupNameFormat.
//
// In case users should be authenticated within a specific scope to
// An example config:
//	connectors:
//		type: keystone
//		id: keystone
//		name: Keystone
//		config:
//			host: http://example:5000
//			domain: Default
//      	adminUsername: demo
//      	adminPassword: DEMO_PASS
//      	adminUserDomain: Default
//      	adminProject: admin
//      	adminDomain: Default
//			includeRolesInGroups: true
//			authScope:
//				projectName: the-users-project
//				domainName: the-projects-domain
//			roleNameFormat: "os_role:%s"
//			groupNameFormat: "os_group:%s"

type Config struct {
	Cloud                string `json:"cloud"`
	Domain               string `json:"domain"`
	Host                 string `json:"host"`
	AdminUsername        string `json:"adminUsername"`
	AdminPassword        string `json:"adminPassword"`
	AdminUserDomainName  string `json:"adminUserDomain"`
	AdminProject         string `json:"adminProject"`
	AdminDomain          string `json:"adminDomain"`
	Prompt               string `json:"prompt"`
	AuthScope            *scope `json:"authScope,omitempty"`
	IncludeRolesInGroups *bool  `json:"includeRolesInGroups,omitempty"`
	RoleNameFormat       string `json:"roleNameFormat,omitempty"`
	GroupNameFormat      string `json:"groupNameFormat,omitempty"`
}

var (
	_ connector.PasswordConnector = &conn{}
	_ connector.RefreshConnector  = &conn{}
)

// Open returns an authentication strategy using Keystone.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	// sanitize configuration with some default values if they have not been provided
	if c.Domain == "" {
		c.Domain = DefaultDomain
	}
	if c.Prompt == "" {
		c.Prompt = DefaultPrompt
	}
	if c.IncludeRolesInGroups == nil {
		include := false
		c.IncludeRolesInGroups = &include
	}
	if c.GroupNameFormat == "" {
		c.GroupNameFormat = DefaultGroupNameFormat
	}
	if c.RoleNameFormat == "" {
		c.RoleNameFormat = DefaultRoleNameFormat
	}

	// gopercloud auth configuration
	authInfo := &clientconfig.AuthInfo{
		AuthURL: c.Host,
		Username: c.AdminUsername,
		Password: c.AdminPassword,
		UserDomainName: c.AdminUserDomainName,
	}

	if c.AdminProject != "" {
		authInfo.ProjectName = c.AdminProject
		authInfo.ProjectDomainName = c.AdminDomain
	} else {
		authInfo.DomainName = c.AdminDomain
	}

	clientOpts := &clientconfig.ClientOpts{
		Cloud: c.Cloud,
		AuthInfo: authInfo,
	}

	authOptions, err := clientconfig.AuthOptions(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("could not evaluate openstack credentials: %v", err)
	}
	authOptions.AllowReauth = true

	providerClient, err := openstack.AuthenticatedClient(*authOptions)
	if err != nil {
		return nil, fmt.Errorf("service-account %s@%s authentication failed: %v", c.AdminUsername, c.Domain, err)
	}

	serviceClient, err := openstack.NewIdentityV3(providerClient, gophercloud.EndpointOpts{})

	return &conn{
		providerClient,
		serviceClient,
		logger,
		c}, nil
}

func (p *conn) Close() error { return nil }

func (p *conn) Login(ctx context.Context, scopes connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	// we need authentication options for the user
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: p.ProviderClient.IdentityEndpoint,
		Username:         username,
		Password:         password,
		DomainName:       p.Config.Domain,
	}

	// set the desired authentication scope
	if p.Config.AuthScope != nil {
		opts.Scope = &gophercloud.AuthScope{
			DomainID:    p.Config.AuthScope.DomainID,
			DomainName:  p.Config.AuthScope.DomainName,
			ProjectID:   p.Config.AuthScope.ProjectID,
			ProjectName: p.Config.AuthScope.ProjectName,
		}
	}

	// authenticate
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return identity, false, err
	}

	// grab attributes from keystone token
	token, err := getTokenDetails(provider)
	if err != nil {
		return identity, false, err
	}

	user, err := p.getUser(token.UserID)
	if err != nil {
		return identity, true, err
	}

	// retrieve user groups
	if scopes.Groups {
		identity.Groups, err = p.getUserGroups(token.UserID)
		if err != nil {
			return identity, true, err
		}
	}

	// add roles from token
	if *p.Config.IncludeRolesInGroups {
		for _, role := range token.Roles {
			identity.Groups = append(identity.Groups, fmt.Sprintf(p.Config.RoleNameFormat, role))
		}
	}

	identity.Username = username + "@" + p.Config.Domain
	identity.UserID = token.UserID
	if email, ok := user.Extra["email"]; ok {
		identity.Email = email.(string)
		identity.EmailVerified = true
	}

	if scopes.OfflineAccess {
		// Encode token for follow up requests such as the groups query and refresh attempts.
		if identity.ConnectorData, err = json.Marshal(token); err != nil {
			return connector.Identity{}, false, fmt.Errorf("keystone: marshal token entry: %v", err)
		}
	}

	return identity, true, nil
}

func (p *conn) Prompt() string {
	return p.Config.Prompt
}

func (p *conn) Refresh(ctx context.Context, scopes connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	var token token

	if err := json.Unmarshal(identity.ConnectorData, &token); err != nil {
		return identity, fmt.Errorf("keystone: failed to unmarshal internal data: %v", err)
	}

	user, err := p.getUser(identity.UserID)
	if err != nil {
		return identity, err
	}

	if !user.Enabled {
		return identity, fmt.Errorf("user %s@%s is disabled", user.Name, p.Config.Domain)
	}

	if scopes.Groups {
		identity.Groups, err = p.getUserGroups(user.ID)
		if err != nil {
			return identity, err
		}
	}

	if *p.Config.IncludeRolesInGroups {
		target := ""
		id := ""
		if token.ProjectID != "" {
			target = "project"
			id = token.ProjectID
		} else {
			if token.DomainID != "" {
				target = "domain"
				id = token.DomainID
			}
		}
		if id != "" {
			userRoles, err := p.getUserRoles(identity.UserID, target, id)
			if err != nil {
				return identity, err
			}
			identity.Groups = append(identity.Groups, userRoles...)
		}
	}
	return identity, nil
}

func getTokenDetails(providerClient *gophercloud.ProviderClient) (*token, error) {
	token := &token{}
	r := providerClient.GetAuthResult()
	if r == nil {
		//ProviderClient did not use openstack.Authenticate(), e.g. because token
		//was set manually with ProviderClient.SetToken()
		return token, errors.New("no AuthResult available")
	}
	switch r := r.(type) {
	case tokens.CreateResult:
		u, err := r.ExtractUser()
		if err != nil {
			return token, err
		}
		token.UserID = u.ID
		p, err := r.ExtractProject()
		if p != nil {
			token.ProjectID = p.ID
			token.DomainID = p.Domain.ID
		}
		tokenRoles, err := r.ExtractRoles()
		if tokenRoles != nil {
			token.Roles = make([]string, 0)
			for _, role := range tokenRoles {
				token.Roles = append(token.Roles, role.Name)
			}
		}
		return token, nil
	default:
		panic(fmt.Sprintf("got unexpected AuthResult type %t", r))
	}
}

func (p *conn) getUser(userID string) (*users.User, error) {
	result := users.Get(p.ServiceClient, userID)
	user, err := result.Extract()
	if err != nil {
		return nil, fmt.Errorf("user-id %s not found: %v", userID, err)
	}
	return user, nil
}

func (p *conn) getUserGroups(userID string) ([]string, error) {
	result := make([]string, 0)

	allPages, err := users.ListGroups(p.ServiceClient, userID).AllPages()
	if err != nil {
		return nil, fmt.Errorf("list groups for user-id %s failed: %v", userID, err)
	}

	allGroups, err := groups.ExtractGroups(allPages)
	if err != nil {
		return nil, fmt.Errorf("extract groups for user-id %s failed: %v", userID, err)
	}

	for _, group := range allGroups {
		result = append(result, fmt.Sprintf(p.Config.GroupNameFormat, group.Name))
	}

	return result, nil
}

func (p *conn) getUserRoles(userID string, target string, id string) ([]string, error) {
	effective := true
	result := make([]string, 0)

	opts := roles.ListAssignmentsOpts{
		UserID:    userID,
		Effective: &effective,
	}

	if id != "" {
		if target == "project" {
			opts.ScopeProjectID = id
		}
		if target == "domain" {
			opts.ScopeDomainID = id
		}
	}

	allPages, err := roles.ListAssignments(p.ServiceClient, opts).AllPages()
	if err != nil {
		return nil, fmt.Errorf("list role assignments for user-id %s failed: %v", userID, err)
	}

	allRoles, err := roles.ExtractRoleAssignments(allPages)
	if err != nil {
		return nil, fmt.Errorf("extract role-assignments for user-id %s failed: %v", userID, err)
	}

	for _, roleAssignment := range allRoles {
		role, err := p.getRole(roleAssignment.Role.ID)
		if err != nil {
			return nil, err
		} else {
			result = append(result, fmt.Sprintf(p.Config.RoleNameFormat, role.Name))
		}
	}

	return result, nil
}

func (p *conn) getRole(roleID string) (*roles.Role, error) {
	result := roles.Get(p.ServiceClient, roleID)
	role, err := result.Extract()
	if err != nil {
		return nil, fmt.Errorf("role-id %s not found: %v", roleID, err)
	}
	return role, nil
}
