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
package config

// CryptoSettings
//
// CryptoSettings encapsulates parameters for the Argon2 password hashing algorithm.
type CryptoSettings struct {
	Memory      uint32 // memory usage
	Iterations  uint32 // number of hashing rounds
	Parallelism uint8  // degree of concurrency
	// ... other key/salt lengths as conceptualized
}

// HTTPHandlerConfig
//
// HTTPHandlerConfig contains server settings for the HTTP/REST server.
type HTTPHandlerConfig struct {
	ListenAddr    string // e.g., ":8080"
	IssueRoute    string //
	ValidateRoute string //
	// ... Additional routes for user management and revocation are included if respective features are enabled.
}

// GRPCHandlerConfig
//
// GRPCHandlerConfig contains server settings for the public gRPC server.
type GRPCHandlerConfig struct {
	ListenAddr string // e.g., ":9000"
}

// AdminGRPCHandlerConfig
//
// AdminGRPCHandlerConfig contains server settings for the administrative gRPC server.
type AdminGRPCHandlerConfig struct {
	ListenAddr string // e.g., ":9001"
}
