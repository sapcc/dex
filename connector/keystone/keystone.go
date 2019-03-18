// Package keystone provides authentication strategy using Keystone.
package keystone

import (
	"context"
	"errors"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
	tokens3 "github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
)

type conn struct {
	Provider   *gophercloud.ProviderClient
	Client     *gophercloud.ServiceClient
	DomainName string
	Host       string
	Logger     log.Logger
	UserPrompt string
}

// Config holds the configuration parameters for Keystone connector.
// Keystone should expose API v3
// An example config:
//	connectors:
//		type: keystone
//		id: keystone
//		name: Keystone
//		config:
//			authURL: http://example:5000
//			domain: Default
//      	adminUsername: demo
//      	adminPassword: DEMO_PASS
//      	adminUserDomain: Default
//      	adminProject: admin
//      	adminProjectDomain: Default
type Config struct {
	DomainName             string `json:"domain"`
	AuthURL                string `json:"authURL"`
	AdminUsername          string `json:"adminUsername"`
	AdminPassword          string `json:"adminPassword"`
	AdminUserDomainName    string `json:"adminUserDomain"`
	AdminProject           string `json:"adminProject"`
	AdminProjectDomainName string `json:"adminProjectDomain"`
	AdminDomainName        string `json:"adminDomain"`
	Prompt                 string `json:"usernamePrompt"`
}

var (
	_ connector.PasswordConnector = &conn{}
	_ connector.RefreshConnector  = &conn{}
)

// Open returns an authentication strategy using Keystone.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: c.AuthURL,
		Username:         c.AdminUsername,
		Password:         c.AdminPassword,
		DomainName:       c.AdminUserDomainName,
		Scope:            &gophercloud.AuthScope{},
		AllowReauth:      true,
	}

	if c.AdminProject != "" {
		opts.Scope.ProjectName = c.AdminProject
		opts.Scope.DomainName = c.AdminProjectDomainName
	} else {
		if c.AdminDomainName != "" {
			opts.Scope.DomainName = c.AdminDomainName
		}
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("admin %s@%s authentication error %v", c.AdminUsername, c.DomainName, err)
	}

	client, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{})

	prompt := c.Prompt
	if prompt == "" {
		prompt = "username"
	}

	return &conn{
		provider,
		client,
		c.DomainName,
		c.AuthURL,
		logger,
		prompt}, nil
}

func (p *conn) Close() error { return nil }

func (p *conn) Login(ctx context.Context, scopes connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: p.Provider.IdentityEndpoint,
		Username:         username,
		Password:         password,
		DomainName:       p.DomainName,
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return identity, false, nil
	}

	userID, err := getAuthenticatedUserID(provider)
	if err != nil {
		return identity, false, err
	}

	if scopes.Groups {
		identity.Groups, err = getUserGroups(p.Client, userID)
		if err != nil {
			return identity, true, err
		}
	}
	identity.Username = username + "@" + p.DomainName
	identity.UserID = userID
	return identity, true, nil
}

func (p *conn) Prompt() string { return p.UserPrompt }

func (p *conn) Refresh(ctx context.Context, scopes connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	user, err := getUser(p.Client, identity.UserID)
	if err != nil {
		return identity, err
	}

	if !user.Enabled {
		return identity, fmt.Errorf("user %s@%s is disabled", user.Name, p.DomainName)
	}

	if scopes.Groups {
		identity.Groups, err = getUserGroups(p.Client, user.ID)
		if err != nil {
			return identity, err
		}
	}
	return identity, nil
}

func getAuthenticatedUserID(providerClient *gophercloud.ProviderClient) (string, error) {
	r := providerClient.GetAuthResult()
	if r == nil {
		//ProviderClient did not use openstack.Authenticate(), e.g. because token
		//was set manually with ProviderClient.SetToken()
		return "", errors.New("no AuthResult available")
	}
	switch r := r.(type) {
	case tokens3.CreateResult:
		u, err := r.ExtractUser()
		if err != nil {
			return "", err
		}
		return u.ID, nil
	default:
		panic(fmt.Sprintf("got unexpected AuthResult type %t", r))
	}
}

func getUser(client *gophercloud.ServiceClient, userID string) (*users.User, error) {
	result := users.Get(client, userID)
	user, err := result.Extract()
	if err != nil {
		return nil, fmt.Errorf("user-id %s not found: %v", userID, err)
	}

	return user, nil
}

func getUserGroups(client *gophercloud.ServiceClient, userID string) ([]string, error) {
	result := make([]string, 0)

	allPages, err := users.ListGroups(client, userID).AllPages()
	if err != nil {
		return nil, fmt.Errorf("list groups for user-id %s failed: %v", userID, err)
	}

	allGroups, err := groups.ExtractGroups(allPages)
	if err != nil {
		return nil, fmt.Errorf("extract groups for user-id %s failed: %v", userID, err)
	}

	for _, group := range allGroups {
		result = append(result, group.Name)
	}

	return result, nil
}
