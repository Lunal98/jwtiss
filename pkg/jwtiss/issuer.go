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

import (
	"context"
	"time"
)

// Issuer
//
// Issuer manages JWT issuance and management.
type Issuer struct {
	// Internal components like database connections, cryptographic keys, and server instances
	// These are not directly exposed as properties in the document but are implied by the system's function.
}

// StartServer initiates the configured HTTP, public gRPC, and/or Admin gRPC servers, listening for incoming requests.
// This method is typically blocking and runs indefinitely until an error occurs or the provided context.Context is canceled.
func (i *Issuer) StartServer(ctx context.Context) error {
	panic("unimplemented")
}

// GetAuthService returns the AuthService object, which encapsulates all public authentication and token validation operations.
func (i *Issuer) GetAuthService() *AuthService {
	panic("unimplemented")
}

// GetAdminService returns the AdminService object, which encapsulates all administrative user and token management operations.
func (i *Issuer) GetAdminService() *AdminService {
	panic("unimplemented")
}

// Claims
//
// Claims represents the structured information contained within a JWT payload.
type Claims struct {
	Subject         string                 // The principal about whom the JWT is issued.
	ExpiresAt       time.Time              // The expiration time of the JWT.
	IssuedAt        time.Time              // The time at which the JWT was issued.
	Issuer          string                 // The identifier of the entity that issued the JWT.
	Audience        []string               // The intended recipients of the JWT.
	JTI             string                 // A unique identifier for the JWT, crucial for revocation.
	Roles           []string               // The roles assigned to the user (e.g., "admin", "user").
	StaticClaims    map[string]interface{} // Global claims configured via .WithStaticClaim().
	UserBoundClaims map[string]interface{} // User-specific claims retrieved from the user_data table, as defined by .WithUserBoundClaimsSchema().
	CustomClaims    map[string]interface{} // Dynamically generated claims from .WithCustomClaimsResolver() or custom claims provided during IssueToken calls.
}

// User
//
// User is a simplified representation of a user account.
type User struct {
	ID        string   // A unique identifier for the user (e.g., derived from username or a UUID).
	Username  string   //
	Roles     []string // The roles assigned to this user.
	IsDeleted bool     // A flag indicating if the user account is soft-deleted within the admin_access table.
}
