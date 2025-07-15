/*
Copyright © 2025 Alex Bedo <alex98hun@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package jwtiss

// AuthService
//
// AuthService exposes methods for user authentication and public token operations.
// This object is obtained via Issuer.GetAuthService().
type AuthService struct {
	// Internal fields related to authentication logic and database interaction
}

// LoginUser authenticates a user against the stored credentials. Upon successful authentication, a new JWT is issued and returned.
// Parameters: username (string), password (string).
// Returns: The signed JWT string, or an error if authentication fails (e.g., ErrInvalidCredentials, ErrUserNotFound).
func (s *AuthService) LoginUser(username, password string) (string, error) {
	panic("unimplemented")
}

// RegisterUser creates a new user account in the database. Optional roles can be assigned during registration.
// Parameters: username (string), password (string), roles (variadic string slice).
// Returns: A *User object representing the newly created user, or an error (e.g., ErrUserAlreadyExists).
// This method is typically exposed via HTTP/gRPC handlers only if AllowSelfRegistration is enabled or through the Admin gRPC API.
func (s *AuthService) RegisterUser(username, password string, roles ...string) (*User, error) {
	panic("unimplemented")
}

// ValidateToken validates the provided JWT string. This includes verifying the signature, checking expiration, and consulting the revocation lists.
// Parameters: tokenString (string).
// Returns: A *Claims object containing the verified payload claims, or an error if the token is invalid (e.g., ErrInvalidToken, ErrTokenExpired, ErrTokenRevoked).
func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	panic("unimplemented")
}

// LogoutUser invalidates the currently active access token and any associated refresh token (if implemented) for the user.
// This effectively logs the user out by marking their tokens as revoked in the database.
// Parameters: tokenString (string) - the access token to revoke.
// Returns: An error if the token cannot be revoked or is invalid.
func (s *AuthService) LogoutUser(tokenString string) error {
	panic("unimplemented")
}

// GetJWKS returns the JSON Web Key Set (JWKS) containing the public keys used by this issuer for token verification.
// This function allows clients to dynamically retrieve the necessary public keys to validate JWTs issued by this service.
// Returns: An interface representing the JWKS structure (e.g., a Go struct that can be marshaled to JSON), or an error.
func (s *AuthService) GetJWKS() (interface{}, error) {
	panic("unimplemented")
}

// AdminService
//
// AdminService exposes methods for administrative user and token management.
// This object is obtained via Issuer.GetAdminService().
type AdminService struct {
	// Internal fields related to administrative logic and database interaction
}

// AdminRevokeToken explicitly adds a token's unique ID (jti) to the revocation list, rendering it immediately invalid.
// This operation requires administrative authorization.
// Parameters: jti (string) - the JWT ID to revoke; actorClaims (*Claims) - the claims of the administrator performing the revocation, used for permission checks.
// Returns: An error if revocation fails (e.g., ErrPermissionDenied).
func (s *AdminService) AdminRevokeToken(jti string, actorClaims *Claims) error {
	panic("unimplemented")
}

// AdminDeleteUser removes a user account from the system. This operation requires administrative authorization.
// Parameters: userID (string) - the ID of the user to delete; actorClaims (*Claims) - the claims of the administrator performing the deletion.
// Returns: An error if deletion fails (e.g., ErrPermissionDenied, ErrUserNotFound).
func (s *AdminService) AdminDeleteUser(userID string, actorClaims *Claims) error {
	panic("unimplemented")
}

// AdminListUsers retrieves a list of all registered user accounts. This operation requires administrative authorization.
// Parameters: actorClaims (*Claims) - the claims of the administrator requesting the list.
// Returns: A slice of *User objects, or an error (e.g., ErrPermissionDenied).
func (s *AdminService) AdminListUsers(actorClaims *Claims) ([]*User, error) {
	panic("unimplemented")
}

// AdminUpdateUserRoles modifies the roles assigned to a specific user. This operation requires administrative authorization.
// Parameters: userID (string) - the ID of the user whose roles are to be updated; newRoles ([]string) - the new set of roles; actorClaims (*Claims) - the claims of the administrator performing the update.
// Returns: An error if the update fails (e.g., ErrPermissionDenied, ErrUserNotFound).
func (s *AdminService) AdminUpdateUserRoles(userID string, newRoles []string, actorClaims *Claims) error {
	panic("unimplemented")
}

// IsTokenRevoked internally checks if a specific token (identified by its jti) is present on the revocation list.
// This method is primarily used by ValidateToken.
// Parameters: jti (string).
// Returns: true if revoked, false otherwise, or an error.
func (s *AdminService) IsTokenRevoked(jti string) (bool, error) {
	panic("unimplemented")
}
