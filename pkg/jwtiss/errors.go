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

import "errors"

// Custom Error Types
//
// These are distinct and descriptive error types for various failure conditions.
var (
	ErrInvalidToken           = errors.New("invalid token")            // Indicates a malformed JWT or a failed signature verification.
	ErrTokenExpired           = errors.New("token expired")            // Signifies that the JWT has passed its expiration date.
	ErrTokenRevoked           = errors.New("token revoked")            // Denotes that the JWT has been explicitly invalidated.
	ErrUserNotFound           = errors.New("user not found")           // Occurs when a requested user account does not exist.
	ErrInvalidCredentials     = errors.New("invalid credentials")      // Raised when provided username or password do not match.
	ErrUserAlreadyExists      = errors.New("user already exists")      // Occurs during an attempt to register a username that is already taken.
	ErrPermissionDenied       = errors.New("permission denied")        // Indicates that the authenticated user lacks the necessary roles or privileges to perform a requested action.
	ErrConfiguration          = errors.New("configuration error")      // Signifies an issue with the library's setup or configuration.
	ErrDatabaseSchemaMismatch = errors.New("database schema mismatch") // Occurs if the provided UserBoundClaimsSchema is inconsistent with the existing user_data table structure.
)
