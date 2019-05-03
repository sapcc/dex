package keystone

import (
	"context"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
	"github.com/gophercloud/utils/openstack/clientconfig"
	"reflect"
	"strings"
	"testing"

	"github.com/dexidp/dex/connector"
)

const (
	invalidPass = "WRONG_PASS"

	testUser       = "test_user"
	testPass       = "test_pass"
	testEmail      = "test@example.com"
	testGroup      = "test_group"
	testDomainID   = "default"
	testDomainName = "Default"
)

var (
	provider *gophercloud.ProviderClient
	client   *gophercloud.ServiceClient
	config *Config
)

// create a testuser
func createUser(t *testing.T, userDomainID, userName, userEmail, userPass string) string {
	t.Helper()

	createOpts := users.CreateOpts{
		Name:     userName,
		Password: userPass,
		Enabled:  gophercloud.Enabled,
		DomainID: userDomainID,
		Extra: map[string]interface{}{
			"email": userEmail,
		},
	}

	user, err := users.Create(client, createOpts).Extract()
	if err != nil {
		t.Fatal(err.Error())
	}

	roleID := getRole(t, "admin").ID

	err = roles.Assign(client, roleID, roles.AssignOpts{
		UserID:   user.ID,
		DomainID: userDomainID,
	}).ExtractErr()

	if err != nil {
		t.Fatal(err.Error())
	}

	return user.ID
}

// delete user
func deleteUser(t *testing.T, userID string) {
	t.Helper()
	if userID != "" {
		users.Delete(client, userID).ExtractErr()
	}
}

// create a group
func createGroup(t *testing.T, domainID, description, name string) string {
	t.Helper()

	createOpts := groups.CreateOpts{
		Name:        name,
		DomainID:    domainID,
		Description: description,
	}

	group, err := groups.Create(client, createOpts).Extract()
	if err != nil {
		t.Fatal(err.Error())
	}

	return group.ID
}

// delete user
func deleteGroup(t *testing.T, groupID string) {
	t.Helper()
	if groupID != "" {
		groups.Delete(client, groupID).ExtractErr()
	}
}

func addUserToGroup(t *testing.T, groupID, userID string) error {
	t.Helper()

	err := users.AddToGroup(client, groupID, userID).ExtractErr()

	if err != nil {
		t.Fatal(err.Error())
	}
	return nil
}

func getRole(t *testing.T, name string) roles.Role {
	t.Helper()

	var result roles.Role

	listOpts := roles.ListOpts{
		Name: name,
	}
	allPages, err := roles.List(client, listOpts).AllPages()
	if err != nil {
		t.Error(err.Error())
	}
	allRoles, err := roles.ExtractRoles(allPages)
	if err != nil {
		t.Error(err.Error())
	}

	for _, role := range allRoles {
		result = role
	}

	return result
}

func TestIncorrectCredentialsLogin(t *testing.T) {
	setupClient(t)
	userID := createUser(t, testDomainID, testUser, testEmail, testPass)
	defer deleteUser(t, userID)

	c := conn{Config: config, ProviderClient: provider, ServiceClient: client}
	s := connector.Scopes{OfflineAccess: true, Groups: true}
	_, validPW, err := c.Login(context.Background(), s, testUser, invalidPass)

	if validPW {
		t.Fatal("Incorrect password check")
	}

	if err == nil {
		t.Fatal("Error should be returned when invalid password is provided")
	}

	if !strings.Contains(err.Error(), "Authentication failed") {
		t.Fatalf("Unrecognized error %v, expecting Authentication failed", err)
	}
}

func TestValidUserLogin(t *testing.T) {
	setupClient(t)
	userID := createUser(t, testDomainID, testUser, testEmail, testPass)
	defer deleteUser(t, userID)

	c := conn{Config: config, ProviderClient: provider, ServiceClient: client}
	s := connector.Scopes{OfflineAccess: true, Groups: true}
	identity, validPW, err := c.Login(context.Background(), s, testUser, testPass)

	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(identity)

	if !validPW {
		t.Fatal("Valid password was not accepted")
	}
}

func TestUseRefreshToken(t *testing.T) {
	setupClient(t)
	userID := createUser(t, testDomainID, testUser, testEmail, testPass)
	defer deleteUser(t, userID)
	groupID := createGroup(t, testDomainID, "Test group description", testGroup)
	defer deleteGroup(t, groupID)
	addUserToGroup(t, groupID, userID)

	c := conn{Config: config, ProviderClient: provider, ServiceClient: client}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, err := c.Login(context.Background(), s, testUser, testPass)
	if err != nil {
		t.Fatal(err.Error())
	}

	identityRefresh, err := c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	expectEquals(t, 1, len(identityRefresh.Groups))
	expectEquals(t, testGroup, string(identityRefresh.Groups[0]))
}

func TestUseRefreshTokenUserDeleted(t *testing.T) {
	setupClient(t)
	userID := createUser(t, testDomainID, testUser, testEmail, testPass)
	defer deleteUser(t, userID)

	c := conn{Config: config, ProviderClient: provider, ServiceClient: client}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, err := c.Login(context.Background(), s, testUser, testPass)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, err = c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	deleteUser(t, userID)
	_, err = c.Refresh(context.Background(), s, identityLogin)

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestUseRefreshTokenGroupsChanged(t *testing.T) {
	setupClient(t)
	userID := createUser(t, testDomainID, testUser, testEmail, testPass)
	defer deleteUser(t, userID)

	c := conn{Config: config, ProviderClient: provider, ServiceClient: client}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, err := c.Login(context.Background(), s, testUser, testPass)
	if err != nil {
		t.Fatal(err.Error())
	}

	identityRefresh, err := c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	expectEquals(t, 0, len(identityRefresh.Groups))

	groupID := createGroup(t, testDomainID, "Test group", testGroup)
	defer deleteGroup(t, groupID)
	addUserToGroup(t, groupID, userID)

	identityRefresh, err = c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}

	expectEquals(t, 1, len(identityRefresh.Groups))
}

func TestNoGroupsInScope(t *testing.T) {
	setupClient(t)
	userID := createUser(t, testDomainID, testUser, testEmail, testPass)
	defer deleteUser(t, userID)

	c := conn{Config: config, ProviderClient: provider, ServiceClient: client}
	s := connector.Scopes{OfflineAccess: true, Groups: false}

	groupID := createGroup(t, testDomainID, "Test group description", testGroup)
	defer deleteGroup(t, groupID)

	addUserToGroup(t, groupID, userID)

	identityLogin, _, err := c.Login(context.Background(), s, testUser, testPass)
	if err != nil {
		t.Fatal(err.Error())
	}
	expectEquals(t, 0, len(identityLogin.Groups))

	identityRefresh, err := c.Refresh(context.Background(), s, identityLogin)
	if err != nil {
		t.Fatal(err.Error())
	}
	expectEquals(t, 0, len(identityRefresh.Groups))
}

func setupClient(t *testing.T) {
	authOpts := &clientconfig.ClientOpts{}

	var err error

	provider, err = clientconfig.AuthenticatedClient(authOpts)
	if err != nil {
		t.Skipf("Keystone auth environment not set, skipping: %v", err)
		return
	}

	client, err = openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{})
	if err != nil {
		t.Fatal(err.Error())
		return
	}

	var rig = false
	config = &Config{Domain:testDomainName, IncludeRolesInGroups: & rig, GroupNameFormat: "%s"}
}

func expectEquals(t *testing.T, a interface{}, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Expected %v to be equal %v", a, b)
	}
}
