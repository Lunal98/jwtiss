Project Design Document: Go JWT Issuer Server Library

Document Version: 1.1 Date: July 15, 2025 Author(s): Alex

## Introduction and Project Goal

What is this project about? This document describes the design for a Go language library that facilitates the creation and management of JSON Web Tokens (JWTs). JWTs serve as secure, self-contained digital identities that enable different components of a system to verify user identity and authorization. This library aims to streamline the process of issuing and managing JWTs, alongside integrated user account management.

Why are we building it? The objective is to provide a robust, secure, and flexible tool for Go developers requiring authentication and authorization capabilities in their applications. The design prioritizes ease of integration with common architectural patterns while allowing for extensive customization to meet specific application requirements.

Key Features We Aim For:

- **JWT Issuance:** Generation of new JWTs for authenticated users.
    
- **Secure User Management:** Persistent storage of user credentials (usernames, securely hashed passwords) and assigned roles within a database.
    
- **Token Revocation:** Capability to immediately invalidate active JWTs and refresh tokens, irrespective of their original expiration time.
    
- **Refresh Token Management:** Comprehensive implementation of refresh token issuance, validation, and secure rotation strategies.
    
- **Administrative Features:** Dedicated functionalities for administrators to manage users and tokens, exposed via a specialized gRPC API.
    
- **Simplified Configuration:** Provision of sensible default settings to enable rapid deployment with minimal configuration.
    
- **Flexible Integration:** Support for integration with both standard web protocols (HTTP/REST) and high-performance inter-service communication (gRPC).
    

## Core Concepts: What is a JWT?

A JWT is a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT are encoded as a JSON object that is digitally signed. A JWT typically comprises three parts:

- **Header:** Specifies the token's type (e.g., JWT) and the cryptographic algorithm used for signing (e.g., HMAC SHA256, RSA).
    
- **Payload (Claims):** Contains the actual data, or "claims," about an entity (typically the user) and additional metadata. Common claims include the subject identifier, expiration time, issuance time, issuer, audience, and user roles.
    
- **Signature:** A cryptographic signature generated using the header, the payload, and a secret key. This signature ensures the token's integrity and authenticity, verifying that the token has not been tampered with and originates from a trusted source.
    

## Overall Design Approach

The library is designed using a **Builder Pattern**. This architectural pattern provides a flexible and fluent interface for constructing complex `Issuer` objects step-by-step. Instead of a monolithic constructor, the Builder allows developers to configure various components and settings incrementally. This approach offers several advantages:

- **Configurability:** Enables easy setup with predefined default options while allowing for granular customization.
    
- **Readability:** Promotes clear and self-documenting configuration code.
    
- **Maintainability:** Facilitates the addition of new features and configuration options without complicating the core `Issuer` object's interface.
    
- **Separation of Concerns:** Clearly separates the construction logic from the `Issuer`'s operational logic.
    

### Handler Implementation Architecture

When designing the interaction between the core `Issuer` logic and external handlers (HTTP, gRPC), a few architectural approaches can be considered.

Chosen Approach: The **Dedicated Service Layer (Option 2)**, implemented as a refinement of Option 2, is the preferred architectural choice. This approach balances the simplicity of a central `Issuer` object for the library user with the internal robustness, testability, and clear separation of concerns provided by explicit service interfaces. The `Issuer` struct will implement these service interfaces, and the library's internal handlers will consume the `Issuer` instance cast to the appropriate interface.

### Project Structure (Directories and Packages)

A common and effective Go project structure often follows a pattern that separates concerns and promotes modularity. Here's the suggested layout for the JWT Issuer library:

**`jwt-issuer-library/`**

- **`cmd/`**: Contains main applications or executables. In a library project, this is typically for example usage or a demonstration server.
    
    - **`example-server/`**: A simple server application that imports and uses your `jwt-issuer-library` to demonstrate how to configure and run it.
        
- **`internal/`**: This directory is for private application and library code. Code within `internal` cannot be imported by other Go modules. This is excellent for encapsulating implementation details that are not part of the public API.
    
    - **`auth/`**: Contains the core logic for the `AuthService`, including user authentication, token issuance, validation, and logout. `claims.go` would define your `Claims` structure.
        
    - **`admin/`**: Houses the implementation for the `AdminService`, covering administrative tasks like user management (delete, list, update roles) and token revocation. `user.go` would define your `User` structure.
        
    - **`database/`**: Defines the database interfaces and common database operations.
        
        - **`sqlite/`**: SQLite specific implementation.
            
        - **`postgres/`**: PostgreSQL specific implementation (if supported).
            
        - `models.go`: Contains the Go structs that map to your database tables (`users`, `user_data`, `admin_access`, `active_access_tokens`, `active_refresh_tokens`).
            
        - _Note on Database Inference:_ The library will infer the database type from the connection string provided to `.WithDatabase(connString string)`. For example, a `connString` starting with `sqlite://` or a file path would indicate SQLite, while `postgres://` would indicate PostgreSQL.
            
    - **`crypto/`**: Handles cryptographic operations, primarily password hashing (Argon2) and potentially interfaces for key management.
        
    - **`server/`**: Contains the implementations for the various server types (HTTP, gRPC, Admin gRPC).
        
        - **`http/`**: HTTP handler logic.
            
        - **`grpc/`**: Public gRPC service implementation.
            
        - **`admin_grpc/`**: Administrative gRPC service implementation.
            
    - **`config/`**: Holds structures and logic related to configuration settings, such as `HTTPHandlerConfig`, `GRPCHandlerConfig`, and `CryptoSettings`.
        
- **`pkg/`**: Contains library code that is safe to be used by external applications. This is your public API.
    
    - **`jwtissuer/`**: This would be the main package for your library.
        
        - `issuer.go`: Defines the `Issuer` struct and its core methods (`StartServer`, `GetAuthService`, `GetAdminService`).
            
        - `builder.go`: Contains the `IssuerBuilder` and all its chained configuration methods (e.g., `WithHMACKey`, `WithDatabase`).
            
        - `errors.go`: Defines all the custom error types (`ErrInvalidToken`, `ErrUserNotFound`, etc.) that are part of your public API.
            
        - `interfaces.go`: Defines the public interfaces for `AuthService` and `AdminService` that your `Issuer` implements. This allows users to interact with these services via interfaces, promoting loose coupling.
            
- **`go.mod` / `go.sum`**: Standard Go module files for dependency management.
    
- **`README.md`**: Project documentation, usage instructions, etc.
    

**Key Advantages of this Structure:**

- **Clear Separation of Concerns:** Each package has a well-defined responsibility.
    
- **Encapsulation:** `internal/` keeps implementation details private, ensuring users only interact with your public `pkg/jwtissuer` API.
    
- **Testability:** Smaller, focused packages are easier to test independently.
    
- **Maintainability:** Changes in one area (e.g., database implementation) are less likely to impact others.
    
- **Scalability:** The structure can easily accommodate new features or integrations (e.g., adding support for more database types or authentication methods).
    

## Public API Interface (Library Usage)

This section details the primary interfaces and functions provided by the library for application integration.

### The `Issuer` Builder

The `Issuer` Builder is the entry point for configuring and initializing the JWT issuance and management system. **Starting Point:** `jwtissuer.NewIssuerBuilder()` This method returns a new `IssuerBuilder` instance, providing a clean slate for system configuration.

**Configuration Steps (Chained Methods):** These methods are chained to apply specific configurations.

- `.WithHMACKey(key []byte)`
    
    - **Purpose:** Sets the secret key for HMAC (Hash-based Message Authentication Code) digital signatures.
        
    - **Requirement:** One of the key methods (`WithHMACKey`, `WithRSAKey`, or `WithECDSAKey`) must be provided.
        
- `.WithRSAKey(privateKey *rsa.PrivateKey)`
    
    - **Purpose:** Sets an RSA private key for digital signing.
        
    - **Requirement:** One of the key methods must be provided.
        
- `.WithECDSAKey(privateKey *ecdsa.PrivateKey)`
    
    - **Purpose:** Sets an ECDSA private key for digital signing.
        
    - **Requirement:** One of the key methods must be provided.
        
- `.WithSigningMethod(method jwt.SigningMethod)`
    
    - **Purpose:** Explicitly selects the JWT signing algorithm (e.g., HS256, RS512, ES384). If not specified, the library infers a suitable default based on the provided key type.
        
    - **Default:** A sensible default is chosen (e.g., HS256 for HMAC, RS256 for RSA).
        
    - **Constraint:** The selected method must be compatible with the provided key type; validation is performed by the library.
        
- `.WithCryptoSettings(settings *CryptoSettings)`
    
    - **Purpose:** Configures parameters for the Argon2 password hashing algorithm, which is used for secure password storage.
        
    - `CryptoSettings` (Conceptual Structure): Encapsulates parameters such as `Memory` (memory usage), `Iterations` (number of hashing rounds), `Parallelism` (degree of concurrency), and key/salt lengths.
        
    - **Default:** The library applies secure, recommended Argon2 settings.
        
- `.WithTokenExpiry(duration time.Duration)`
    
    - **Purpose:** Establishes the default validity duration for issued JWTs.
        
    - **Type:** A `time.Duration` value (e.g., `15 * time.Minute`, `1 * time.Hour`).
        
    - **Default:** A reasonable default (e.g., 15 minutes or 1 hour).
        
- `.WithIssuer(name string)`
    
    - **Purpose:** Sets the "iss" (issuer) claim in all generated JWTs, identifying the entity that issued the token.
        
    - **Default:** No default; setting this is recommended practice.
        
- `.WithAudience(audience string)`
    
    - **Purpose:** Sets the "aud" (audience) claim, indicating the intended recipient(s) of the JWT. This method can be called multiple times to specify multiple audiences.
        
    - **Default:** No default.
        
- `.WithCustomClaimsResolver(resolver func(username string) (map[string]interface{}, error))`
    
    - **Purpose:** Provides a custom function that is invoked during token issuance. This function receives the `username` and can dynamically generate additional claims, enabling integration with external data sources or complex business logic.
        
    - **Return:** The `resolver` function should return a `map[string]interface{}` containing the claims to be added, or an error.
        
- **Database Configuration:**
    
    - `.WithDatabase(connString string)`
        
        - **Purpose:** Configures the database connection string for persistent storage of user accounts, active tokens, and revocation lists.
            
        - `connString`: A database-specific connection string (e.g., file path for SQLite, connection details for PostgreSQL).
            
        - **Default:** If this method is not invoked, the library defaults to an ephemeral, in-memory SQLite database. This is suitable for testing but results in data loss upon program termination. For production environments, a persistent database connection is mandatory.
            
- **User Management & Admin Features Configuration:**
    
    - `.EnableUserManagement()`
        
        - **Purpose:** Activates user account creation, authentication, and management functionalities.
            
        - **Default:** Disabled by default.
            
        - **Prerequisite:** If enabled, a persistent database must be configured via `WithDatabase` to prevent data loss.
            
    - `.WithInitialAdminUser(username string, password string)`
        
        - **Purpose:** Automatically provisions an initial administrative user upon the first system startup (if the user database is empty). This facilitates initial access to administrative features.
            
        - **Default:** No initial admin user is created.
            
    - `.AllowSelfRegistration(enabled bool)`
        
        - **Purpose:** Controls whether users can create their own accounts via public interfaces.
            
        - **Default:** `false` (self-registration is disabled; user accounts must be created by an administrator).
            
    - `.WithAdminRoleName(name string)`
        
        - **Purpose:** Customizes the name used to identify administrative users within JWT claims.
            
        - **Default:** `"admin"`
            
- **Server Handlers (HTTP/gRPC) Configuration:**
    
    - `.EnableHTTP(config *HTTPHandlerConfig)`
        
        - **Purpose:** Activates the built-in HTTP/REST server, which exposes public endpoints for user login, registration, and token validation.
            
        - `HTTPHandlerConfig` (Conceptual Structure): Contains server settings such as `ListenAddr` (e.g., ":8080"), `IssueRoute`, and `ValidateRoute`. Additional routes for user management and revocation are included if respective features are enabled.
            
        - **Default:** The HTTP server is disabled by default.
            
    - `.EnableGRPC(config *GRPCHandlerConfig)`
        
        - **Purpose:** Activates the built-in gRPC server for public token issuance and validation. gRPC provides a high-performance, language-agnostic communication protocol.
            
        - `GRPCHandlerConfig` (Conceptual Structure): Contains server settings such as `ListenAddr` (e.g., ":9000").
            
        - **Default:** The public gRPC server is disabled by default.
            
    - `.EnableAdminGRPC(config *AdminGRPCHandlerConfig)`
        
        - **Purpose:** Activates a **separate** gRPC server dedicated to administrative operations, including comprehensive user management (registration, deletion, listing, role updates) and explicit token revocation. This segregation enhances security by isolating sensitive operations on a distinct, potentially more restricted, network port.
            
        - `AdminGRPCHandlerConfig` (Conceptual Structure): Contains server settings such as `ListenAddr` (e.g., ":9001").
            
        - **Default:** The Admin gRPC server is disabled by default.
            

**Building the System:**

- `.Build()`
    
    - **Purpose:** Finalizes the `Issuer` configuration and constructs the operational `Issuer` object, along with its associated service layer objects.
        
    - **Returns:** The configured `*Issuer` object, `*AuthService` object, `*AdminService` object, and any error encountered during the build process (e.g., missing cryptographic key).
        

### The `Issuer` Object (Operational Interface)

Once the `Issuer` object is successfully built, its methods provide the core functionalities for JWT and server management.

- `StartServer(ctx context.Context) error`
    
    - **Purpose:** Initiates the configured HTTP, public gRPC, and/or Admin gRPC servers, listening for incoming requests. This method is typically blocking and runs indefinitely until an error occurs or the provided `context.Context` is canceled.
        
- `GetAuthService() *AuthService`
    
    - **Purpose:** Returns the `AuthService` object, which encapsulates all public authentication and token validation operations.
        
    - **Returns:** A pointer to the `AuthService` object.
        
- `GetAdminService() *AdminService`
    
    - **Purpose:** Returns the `AdminService` object, which encapsulates all administrative user and token management operations.
        
    - **Returns:** A pointer to the `AdminService` object.
        

### The `AuthService` Object (Public Service Layer)

The `AuthService` object exposes methods for user authentication and public token operations. This object is obtained via `Issuer.GetAuthService()`.

- `LoginUser(username, password string) (string, error)`
    
    - **Purpose:** Authenticates a user against the stored credentials. Upon successful authentication, a new JWT is issued and returned.
        
    - **Parameters:** `username` (string), `password` (string).
        
    - **Returns:** The signed JWT string, or an error if authentication fails (e.g., `ErrInvalidCredentials`, `ErrUserNotFound`).
        
- `RegisterUser(username, password string, roles ...string) (*User, error)`
    
    - **Purpose:** Creates a new user account in the database. Optional roles can be assigned during registration.
        
    - **Parameters:** `username` (string), `password` (string), `roles` (variadic string slice).
        
    - **Returns:** A `*User` object representing the newly created user, or an error (e.g., `ErrUserAlreadyExists`). This method is typically exposed via HTTP/gRPC handlers only if `AllowSelfRegistration` is enabled or through the Admin gRPC API.
        
- `ValidateToken(tokenString string) (*Claims, error)`
    
    - **Purpose:** Validates the provided JWT string. This includes verifying the signature, checking expiration, and consulting the revocation lists.
        
    - **Parameters:** `tokenString` (string).
        
    - **Returns:** A `*Claims` object containing the verified payload claims, or an error if the token is invalid (e.g., `ErrInvalidToken`, `ErrTokenExpired`, `ErrTokenRevoked`).
        
- `LogoutUser(tokenString string) error`
    
    - **Purpose:** Invalidates the currently active access token and any associated refresh token (if implemented) for the user. This effectively logs the user out by marking their tokens as revoked in the database.
        
    - **Parameters:** `tokenString` (string) - the access token to revoke.
        
    - **Returns:** An error if the token cannot be revoked or is invalid.
        
- `GetJWKS() (interface{}, error)`
    
    - **Purpose:** Returns the JSON Web Key Set (JWKS) containing the public keys used by this issuer for token verification. This function allows clients to dynamically retrieve the necessary public keys to validate JWTs issued by this service.
        
    - **Returns:** An interface representing the JWKS structure (e.g., a Go struct that can be marshaled to JSON), or an error.
        

### The `AdminService` Object (Administrative Service Layer)

The `AdminService` object exposes methods for administrative user and token management. This object is obtained via `Issuer.GetAdminService()`.

- `AdminRevokeToken(jti string, actorClaims *Claims) error`
    
    - **Purpose:** Explicitly adds a token's unique ID (`jti`) to the revocation list, rendering it immediately invalid. This operation requires administrative authorization.
        
    - **Parameters:** `jti` (string) - the JWT ID to revoke; `actorClaims` (`*Claims`) - the claims of the administrator performing the revocation, used for permission checks.
        
    - **Returns:** An error if revocation fails (e.g., `ErrPermissionDenied`).
        
- `AdminDeleteUser(userID string, actorClaims *Claims) error`
    
    - **Purpose:** Removes a user account from the system. This operation requires administrative authorization.
        
    - **Parameters:** `userID` (string) - the ID of the user to delete; `actorClaims` (`*Claims`) - the claims of the administrator performing the deletion.
        
    - **Returns:** An error if deletion fails (e.g., `ErrPermissionDenied`, `ErrUserNotFound`).
        
- `AdminListUsers(actorClaims *Claims) ([]*User, error)`
    
    - **Purpose:** Retrieves a list of all registered user accounts. This operation requires administrative authorization.
        
    - **Parameters:** `actorClaims` (`*Claims`) - the claims of the administrator requesting the list.
        
    - **Returns:** A slice of `*User` objects, or an error (e.g., `ErrPermissionDenied`).
        
- `AdminUpdateUserRoles(userID string, newRoles []string, actorClaims *Claims) error`
    
    - **Purpose:** Modifies the roles assigned to a specific user. This operation requires administrative authorization.
        
    - **Parameters:** `userID` (string) - the ID of the user whose roles are to be updated; `newRoles` ([]string) - the new set of roles; `actorClaims` (`*Claims`) - the claims of the administrator performing the update.
        
    - **Returns:** An error if the update fails (e.g., `ErrPermissionDenied`, `ErrUserNotFound`).
        
- `IsTokenRevoked(jti string) (bool, error)`
    
    - **Purpose:** Internally checks if a specific token (identified by its `jti`) is present on the revocation list. This method is primarily used by `ValidateToken`.
        
    - **Parameters:** `jti` (string).
        
    - **Returns:** `true` if revoked, `false` otherwise, or an error.
        

### Important Data Structures (Information Representation)

- `Claims` (Conceptual Structure): Represents the structured information contained within a JWT payload.
    
    - `Subject` (string): The principal about whom the JWT is issued.
        
    - `ExpiresAt` (time.Time): The expiration time of the JWT.
        
    - `IssuedAt` (time.Time): The time at which the JWT was issued.
        
    - `Issuer` (string): The identifier of the entity that issued the JWT.
        
    - `Audience` ([]string): The intended recipients of the JWT.
        
    - `JTI` (string): A unique identifier for the JWT, crucial for revocation.
        
    - `Roles` ([]string): The roles assigned to the user (e.g., "admin", "user").
        
    - `StaticClaims` (map[string]interface{}): Global claims configured via `.WithStaticClaim()`.
        
    - `UserBoundClaims` (map[string]interface{}): User-specific claims retrieved from the `user_data` table, as defined by `.WithUserBoundClaimsSchema()`.
        
    - `CustomClaims` (map[string]interface{}): Dynamically generated claims from `.WithCustomClaimsResolver()` or custom claims provided during `IssueToken` calls.
        
    - **Note:** The final `Claims` object presented to the application will represent a merged view of all claim sources, with a defined precedence (e.g., `customClaims` overriding `userBoundClaims`, which override `staticClaims` for overlapping keys).
        
- `User` (Conceptual Structure): A simplified representation of a user account.
    
    - `ID` (string): A unique identifier for the user (e.g., derived from username or a UUID).
        
    - `Username` (string)
        
    - `Roles` ([]string): The roles assigned to this user.
        
    - `IsDeleted` (bool): A flag indicating if the user account is soft-deleted within the `admin_access` table.
        

## Database Usage

The library leverages a database for persistent storage of critical system data, structured across several tables:

- `users` table:
    
    - **Purpose:** Stores fundamental user authentication information.
        
    - **Columns:**
        
        - `username` (TEXT PRIMARY KEY): The unique identifier for the user.
            
        - `password_hash` (TEXT): The securely hashed password using Argon2.
            
- `user_data` table (Conditional):
    
    - **Purpose:** Stores custom, user-specific data intended to be included as claims in their JWTs.
        
    - **Creation:** This table is instantiated **only** if the `.WithUserBoundClaimsSchema()` builder method is invoked during configuration.
        
    - **Columns:**
        
        - `username` (TEXT PRIMARY KEY, FOREIGN KEY REFERENCES `users(username)`): Establishes a foreign key relationship to the `users` table.
            
        - **Dynamic Columns:** Additional columns are dynamically generated based on the schema provided in `.WithUserBoundClaimsSchema()`. For instance, a schema of `{"department": "string", "employee_id": "int"}` would result in `department` (TEXT) and `employee_id` (INTEGER) columns.
            
- `admin_access` table:
    
    - **Purpose:** Manages administrative privileges specifically within the JWT issuer system. This is distinct from general user roles.
        
    - **Columns:**
        
        - `username` (TEXT PRIMARY KEY, FOREIGN KEY REFERENCES `users(username)`): Links to the `users` table.
            
        - `roles` (TEXT or JSONB/ARRAY type, depending on DB): Stores roles pertinent to administrative access within the issuer (e.g., "super_admin", "user_manager").
            
        - `is_deleted` (BOOLEAN): A soft-delete flag for administrative accounts, allowing for logical removal without physical deletion.
            
- `active_access_tokens` table:
    
    - **Purpose:** Tracks currently valid access tokens to facilitate explicit revocation.
        
    - **Columns:**
        
        - `jti` (TEXT PRIMARY KEY): The unique JWT ID (`jti` claim) of the access token.
            
        - `username` (TEXT, FOREIGN KEY REFERENCES `users(username)`): The user associated with the token.
            
        - `is_revoked` (BOOLEAN): A flag indicating whether the token has been explicitly revoked.
            
        - `expiry_date` (TIMESTAMP): The scheduled expiration time of the token.
            
- `active_refresh_tokens` table:
    
    - **Purpose:** Tracks currently valid refresh tokens, if refresh token functionality is implemented, for revocation and lifecycle management.
        
    - **Columns:**
        
        - `jti` (TEXT PRIMARY KEY): The unique JWT ID (`jti` claim) of the refresh token.
            
        - `username` (TEXT, FOREIGN KEY REFERENCES `users(username)`): The user associated with the token.
            
        - `is_revoked` (BOOLEAN): A flag indicating whether the token has been explicitly revoked.
            
        - `expiry_date` (TIMESTAMP): The scheduled expiration time of the token.
            

**Default Behavior:** If no database connection string is provided, the library initializes an ephemeral, in-memory SQLite database. While convenient for rapid prototyping and testing, all user data and token state will be lost upon application termination. **Persistent Data:** For production deployments, it is imperative to configure a persistent database (e.g., file-based SQLite, PostgreSQL, MySQL) using the `.WithDatabase(connString string)` method to ensure data durability.

## Default Settings and Security

The library adheres to a "sane defaults" philosophy, providing secure and reasonable configurations out-of-the-box.

- **Argon2 Crypto Settings:** Password hashing employs recommended secure settings for memory, iterations, and parallelism, ensuring robust protection against brute-force attacks.
    
- **Token Expiry:** Issued tokens are configured with a sensible default expiration duration (e.g., 15 minutes to 1 hour), balancing security and usability.
    
- **User Self-Registration:** Disabled by default to prevent unauthorized account creation, requiring administrative intervention for initial user provisioning.
    
- **Initial Admin User:** Support for configuring an initial administrative user streamlines the setup process for new deployments.
    
- `jti` Claim: Every issued token is automatically assigned a unique `jti` (JWT ID), which is crucial for tracking and targeted revocation within the `active_access_tokens` and `active_refresh_tokens` tables.
    
- **Admin gRPC Port:** The default port for the Admin gRPC server is distinct from the public gRPC server (e.g., public on 9000, admin on 9001), enhancing network segmentation and security.
    

## Error Handling

The library provides distinct and descriptive error types for various failure conditions, facilitating robust error handling in consuming applications:

- `ErrInvalidToken`: Indicates a malformed JWT or a failed signature verification.
    
- `ErrTokenExpired`: Signifies that the JWT has passed its expiration date.
    
- `ErrTokenRevoked`: Denotes that the JWT has been explicitly invalidated.
    
- `ErrUserNotFound`: Occurs when a requested user account does not exist.
    
- `ErrInvalidCredentials`: Raised when provided username or password do not match.
    
- `ErrUserAlreadyExists`: Occurs during an attempt to register a username that is already taken.
    
- `ErrPermissionDenied`: Indicates that the authenticated user lacks the necessary roles or privileges to perform a requested action.
    
- `ErrConfiguration`: Signifies an issue with the library's setup or configuration.
    
- `ErrDatabaseSchemaMismatch`: Occurs if the provided `UserBoundClaimsSchema` is inconsistent with the existing `user_data` table structure.
    

## Future Considerations (Not in V1, but Keep in Mind)

These are potential enhancements for future versions of the library:

- **Key Rotation:** Implementation of automated key rotation mechanisms for cryptographic signing keys to enhance long-term security.
    
- **Multiple Key Providers:** Support for retrieving signing keys from diverse sources, such as Key Management Systems (KMS) or JWKS (JSON Web Key Set) endpoints.
    
- **Custom Token Structures:** Increased control over the internal structure and encoding of JWTs beyond standard claims.
    
- **Static Claims Configuration:** The ability to define and include static claims that are consistent across all issued tokens.
    
- **User-Bound Claims Schema:** A mechanism to define a schema for custom user-specific data, stored in a dedicated table, and automatically incorporated as claims in the user's JWT.