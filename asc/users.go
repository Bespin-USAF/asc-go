package asc

import (
	"fmt"
	"net/http"
)

// UsersService handles communication with user and role-related methods of the App Store Connect API
//
// https://developer.apple.com/documentation/appstoreconnectapi/users
// https://developer.apple.com/documentation/appstoreconnectapi/user_invitations
type UsersService service

// UserRole defines model for UserRole.
type UserRole string

// List of UserRole
const (
	// AccessToReports.Downloads reports associated with a role. The Access To Reports role is an additional permission for users with the App Manager, Developer, Marketing, or Sales role. If this permission is added, the user has access to all of your apps.
	UserRoleAccessToReports UserRole = "ACCESS_TO_REPORTS"
	// AccountHolder is responsible for entering into legal agreements with Apple. The person who completes program enrollment is assigned the Account Holder role in both the Apple Developer account and App Store Connect.
	UserRoleAccountHolder UserRole = "ACCOUNT_HOLDER"
	// Admin serves as a secondary contact for teams and has many of the same responsibilities as the Account Holder role. Admins have access to all apps.
	UserRoleAdmin UserRole = "ADMIN"
	// AppManager manages all aspects of an app, such as pricing, App Store information, and app development and delivery.
	UserRoleAppManager UserRole = "APP_MANAGER"
	// CustomerSupport analyzes and responds to customer reviews on the App Store. If a user has only the Customer Support role, they'll go straight to the Ratings and Reviews section when they click on an app in My Apps.
	UserRoleCustomerSupport UserRole = "CUSTOMER_SUPPORT"
	// Developer manages development and delivery of an app.
	UserRoleDeveloper UserRole = "DEVELOPER"
	// Finance manages financial information, including reports and tax forms. A user assigned this role can view all apps in Payments and Financial Reports, Sales and Trends, and App Analytics.
	UserRoleFinance UserRole = "FINANCE"
	// Marketing manages marketing materials and promotional artwork. A user assigned this role will be contacted by Apple if the app is in consideration to be featured on the App Store.
	UserRoleMarketing UserRole = "MARKETING"
	// ReadOnly represents a user with limited access and no write access.
	UserRoleReadOnly UserRole = "READ_ONLY"
	// Sales analyzes sales, downloads, and other analytics for the app.
	UserRoleSales UserRole = "SALES"
	// Technical role is no longer assignable to new users in App Store Connect. Existing users with the Technical role can manage all the aspects of an app, such as pricing, App Store information, and app development and delivery. Techncial users have access to all apps.
	UserRoleTechnical UserRole = "TECHNICAL"
)

// User defines model for User.
type User struct {
	Attributes *struct {
		AllAppsVisible      *bool       `json:"allAppsVisible,omitempty"`
		FirstName           *string     `json:"firstName,omitempty"`
		LastName            *string     `json:"lastName,omitempty"`
		ProvisioningAllowed *bool       `json:"provisioningAllowed,omitempty"`
		Roles               *[]UserRole `json:"roles,omitempty"`
		Username            *string     `json:"username,omitempty"`
	} `json:"attributes,omitempty"`
	ID            string        `json:"id"`
	Links         ResourceLinks `json:"links"`
	Relationships *struct {
		VisibleApps *struct {
			Data  *[]RelationshipsData `json:"data,omitempty"`
			Links *RelationshipsLinks  `json:"links,omitempty"`
			Meta  *PagingInformation   `json:"meta,omitempty"`
		} `json:"visibleApps,omitempty"`
	} `json:"relationships,omitempty"`
	Type string `json:"type"`
}

// UserUpdateRequest defines model for UserUpdateRequest.
type UserUpdateRequest struct {
	Attributes    *UserUpdateRequestAttributes    `json:"attributes,omitempty"`
	ID            string                          `json:"id"`
	Relationships *UserUpdateRequestRelationships `json:"relationships,omitempty"`
	Type          string                          `json:"type"`
}

// UserUpdateRequestAttributes are attributes for UserUpdateRequest
type UserUpdateRequestAttributes struct {
	AllAppsVisible      *bool       `json:"allAppsVisible,omitempty"`
	ProvisioningAllowed *bool       `json:"provisioningAllowed,omitempty"`
	Roles               *[]UserRole `json:"roles,omitempty"`
}

// UserUpdateRequestRelationships are relationships for UserUpdateRequest
type UserUpdateRequestRelationships struct {
	VisibleApps *struct {
		Data *[]RelationshipsData `json:"data,omitempty"`
	} `json:"visibleApps,omitempty"`
}

// UserResponse defines model for UserResponse.
type UserResponse struct {
	Data     User          `json:"data"`
	Included *[]App        `json:"included,omitempty"`
	Links    DocumentLinks `json:"links"`
}

// UsersResponse defines model for UsersResponse.
type UsersResponse struct {
	Data     []User             `json:"data"`
	Included *[]App             `json:"included,omitempty"`
	Links    PagedDocumentLinks `json:"links"`
	Meta     *PagingInformation `json:"meta,omitempty"`
}

// UserVisibleAppsLinkagesResponse defines model for UserVisibleAppsLinkagesResponse.
type UserVisibleAppsLinkagesResponse struct {
	Data  []RelationshipsData `json:"data"`
	Links PagedDocumentLinks  `json:"links"`
	Meta  *PagingInformation  `json:"meta,omitempty"`
}

// ListUsersQuery is the query params structure for ListUsers
type ListUsersQuery struct {
	FieldsApps        *[]string `url:"fields[apps],omitempty"`
	FieldsUsers       *[]string `url:"fields[users],omitempty"`
	FilterRoles       *[]string `url:"filter[roles],omitempty"`
	FilterVisibleApps *[]string `url:"filter[visibleApps],omitempty"`
	FilterUsername    *[]string `url:"filter[username],omitempty"`
	Limit             *int      `url:"limit,omitempty"`
	LimitVisibleApps  *int      `url:"limit[visibleApps],omitempty"`
	Include           *[]string `url:"include,omitempty"`
	Sort              *[]string `url:"sort,omitempty"`
	Cursor            *string   `url:"cursor,omitempty"`
}

// GetUserQuery is the query params structure for GetUser
type GetUserQuery struct {
	FieldsApps       *[]string `url:"fields[apps],omitempty"`
	FieldsUsers      *[]string `url:"fields[users],omitempty"`
	Include          *[]string `url:"include,omitempty"`
	Limit            *int      `url:"limit,omitempty"`
	LimitVisibleApps *int      `url:"limit[visibleApps],omitempty"`
}

// ListVisibleAppsQuery is the query params structure for ListVisibleAppsForUser
type ListVisibleAppsQuery struct {
	FieldsApps *[]string `url:"fields[apps],omitempty"`
	Limit      *int      `url:"limit,omitempty"`
	Cursor     *string   `url:"cursor,omitempty"`
}

// ListVisibleAppsByResourceIDQuery is the query params structure for ListVisibleAppsByResourceIDForUser
type ListVisibleAppsByResourceIDQuery struct {
	Limit  *int    `url:"limit,omitempty"`
	Cursor *string `url:"cursor,omitempty"`
}

// ListUsers gets a list of the users on your team.
func (s *UsersService) ListUsers(params *ListUsersQuery) (*UsersResponse, *http.Response, error) {
	res := new(UsersResponse)
	resp, err := s.client.get("users", params, res)
	return res, resp, err
}

// GetUser gets information about a user on your team, such as name, roles, and app visibility.
func (s *UsersService) GetUser(id string, params *GetUserQuery) (*UserResponse, *http.Response, error) {
	url := fmt.Sprintf("users/%s", id)
	res := new(UserResponse)
	resp, err := s.client.get(url, params, res)
	return res, resp, err
}

// UpdateUser changes a user's role, app visibility information, or other account details.
func (s *UsersService) UpdateUser(id string, body *UserUpdateRequest) (*UserResponse, *http.Response, error) {
	url := fmt.Sprintf("users/%s", id)
	res := new(UserResponse)
	resp, err := s.client.patch(url, body, res)
	return res, resp, err
}

// RemoveUser removes a user from your team.
func (s *UsersService) RemoveUser(id string) (*http.Response, error) {
	url := fmt.Sprintf("users/%s", id)
	return s.client.delete(url, nil)
}

// ListVisibleAppsForUser gets a list of apps that a user on your team can view.
func (s *UsersService) ListVisibleAppsForUser(id string, params *ListVisibleAppsQuery) (*AppsResponse, *http.Response, error) {
	url := fmt.Sprintf("users/%s/visibleApps", id)
	res := new(AppsResponse)
	resp, err := s.client.get(url, params, res)
	return res, resp, err
}

// ListVisibleAppsByResourceIDForUser gets a list of app resource IDs to which a user on your team has access.
func (s *UsersService) ListVisibleAppsByResourceIDForUser(id string, params *ListVisibleAppsByResourceIDQuery) (*UserVisibleAppsLinkagesResponse, *http.Response, error) {
	url := fmt.Sprintf("users/%s/relationships/visibleApps", id)
	res := new(UserVisibleAppsLinkagesResponse)
	resp, err := s.client.get(url, params, res)
	return res, resp, err
}

// AddVisibleAppsForUser gives a user on your team access to one or more apps.
func (s *UsersService) AddVisibleAppsForUser(id string, linkages *[]RelationshipsData) (*http.Response, error) {
	return s.client.post("appStoreReviewDetails", linkages, nil)
}

// UpdateVisibleAppsForUser replaces the list of apps a user on your team can see.
func (s *UsersService) UpdateVisibleAppsForUser(id string, linkages *[]RelationshipsData) (*http.Response, error) {
	url := fmt.Sprintf("users/%s/relationships/visibleApps", id)
	return s.client.patch(url, linkages, nil)
}

// RemoveVisibleAppsFromUser removes a user on your team’s access to one or more apps.
func (s *UsersService) RemoveVisibleAppsFromUser(id string, linkages *[]RelationshipsData) (*http.Response, error) {
	url := fmt.Sprintf("users/%s/relationships/visibleApps", id)
	return s.client.delete(url, linkages)
}
