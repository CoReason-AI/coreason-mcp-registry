package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	"github.com/modelcontextprotocol/registry/internal/config"
)

// PermissionAction represents the type of action that can be performed
type PermissionAction string

const (
	PermissionActionPublish PermissionAction = "publish"
	// PermissionActionEdit allows editing server configuration.
	PermissionActionEdit PermissionAction = "edit"
)

type Permission struct {
	Action          PermissionAction `json:"action"`   // The action type (publish or edit)
	ResourcePattern string           `json:"resource"` // e.g., "io.github.username/*"
}

// JWTClaims represents the claims for the Registry JWT token
type JWTClaims struct {
	jwt.RegisteredClaims
	// Authentication method used to obtain this token
	AuthMethod        Method       `json:"auth_method"`
	AuthMethodSubject string       `json:"auth_method_sub"`
	Permissions       []Permission `json:"permissions"`
}

type TokenResponse struct {
	RegistryToken string `json:"registry_token"`
	ExpiresAt     int    `json:"expires_at"`
}

// JWTManager handles JWT token operations and OIDC validation
type JWTManager struct {
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	tokenDuration time.Duration

	// OIDC Configurations
	oidcEnabled      bool
	oidcIssuer       string
	oidcClientID     string
	oidcPublishPerms string
	oidcEditPerms    string

	// Thread-safe lazy-loading state for OIDC
	mu           sync.RWMutex
	oidcVerifier *oidc.IDTokenVerifier
}

func NewJWTManager(cfg *config.Config) *JWTManager {
	seed, err := hex.DecodeString(cfg.JWTPrivateKey)
	if err != nil {
		panic(fmt.Sprintf("JWTPrivateKey must be a valid hex-encoded string: %v", err))
	}

	// Require a valid Ed25519 seed (32 bytes)
	if len(seed) != ed25519.SeedSize {
		panic(fmt.Sprintf("JWTPrivateKey seed must be exactly %d bytes for Ed25519, got %d bytes", ed25519.SeedSize, len(seed)))
	}

	// Generate the full Ed25519 key pair from the seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &JWTManager{
		privateKey:       privateKey,
		publicKey:        publicKey,
		tokenDuration:    5 * time.Minute, // 5-minute tokens as per requirements
		oidcEnabled:      cfg.OIDCEnabled,
		oidcIssuer:       cfg.OIDCIssuer,
		oidcClientID:     cfg.OIDCClientID,
		oidcPublishPerms: cfg.OIDCPublishPerms,
		oidcEditPerms:    cfg.OIDCEditPerms,
	}
}

// getOIDCVerifier returns a thread-safe, lazily initialized IDTokenVerifier
func (j *JWTManager) getOIDCVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	if !j.oidcEnabled {
		return nil, fmt.Errorf("OIDC is not enabled")
	}

	// Read lock check
	j.mu.RLock()
	verifier := j.oidcVerifier
	j.mu.RUnlock()

	if verifier != nil {
		return verifier, nil
	}

	// Write lock block
	j.mu.Lock()
	defer j.mu.Unlock()

	// Double check
	if j.oidcVerifier != nil {
		return j.oidcVerifier, nil
	}

	// Bounded initialization timeout to prevent hanging the HTTP server.
	// Uses WithoutCancel so client request cancellation doesn't cancel key fetching,
	// satisfying the contextcheck linter.
	initCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(initCtx, j.oidcIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider %q: %w", j.oidcIssuer, err)
	}

	j.oidcVerifier = provider.Verifier(&oidc.Config{ClientID: j.oidcClientID})
	return j.oidcVerifier, nil
}

// GenerateTokenResponse generates a new Registry JWT token
func (j *JWTManager) GenerateTokenResponse(_ context.Context, claims JWTClaims) (*TokenResponse, error) {
	// Check whether they have global permissions (used by admins)
	hasGlobalPermissions := false
	for _, perm := range claims.Permissions {
		if perm.ResourcePattern == "*" {
			hasGlobalPermissions = true
			break
		}
	}

	// Check permissions against denylist, provided they are not an admin.
	// Probe two synthetic resources per blocked namespace so that both the
	// slash-suffix patterns (e.g. com.evil/*) and the dot-wildcard patterns
	// (e.g. com.evil.mailer.* — granted to a subdomain claimant) are
	// detected. Probing only "<blocked>/test" misses the dot-wildcard form
	// because the prefix match against "com.evil.mailer." does not start
	// with "com.evil/test".
	if !hasGlobalPermissions {
		for _, blockedNamespace := range BlockedNamespaces {
			if j.HasPermission(blockedNamespace+"/test", PermissionActionPublish, claims.Permissions) ||
				j.HasPermission(blockedNamespace+".test/x", PermissionActionPublish, claims.Permissions) {
				return nil, fmt.Errorf("your namespace is blocked. raise an issue at https://github.com/modelcontextprotocol/registry/ if you think this is a mistake")
			}
		}
	}

	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(j.tokenDuration))
	}
	if claims.NotBefore == nil {
		claims.NotBefore = jwt.NewNumericDate(time.Now())
	}
	if claims.Issuer == "" {
		claims.Issuer = "mcp-registry"
	}

	// Create token with claims
	token := jwt.NewWithClaims(&jwt.SigningMethodEd25519{}, claims)

	// Sign token with Ed25519 private key
	tokenString, err := token.SignedString(j.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &TokenResponse{
		RegistryToken: tokenString,
		ExpiresAt:     int(claims.ExpiresAt.Unix()),
	}, nil
}

// ValidateToken validates a Registry JWT token, falling back to OIDC if configured
func (j *JWTManager) ValidateToken(ctx context.Context, tokenString string) (*JWTClaims, error) {
	// Parse unverified header to route by algorithm first (performance and algorithm confusion defense)
	parser := jwt.NewParser()
	var rawClaims jwt.MapClaims
	token, _, err := parser.ParseUnverified(tokenString, &rawClaims)

	if err == nil && token.Header["alg"] == "EdDSA" {
		return j.validateEdDSAToken(tokenString)
	}

	// Fallback to OIDC validation if EdDSA validation doesn't match or isn't EdDSA alg
	if !j.oidcEnabled {
		if err != nil {
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}
		return nil, fmt.Errorf("failed to parse token: invalid signing method")
	}

	verifier, oidcErr := j.getOIDCVerifier(ctx)
	if oidcErr != nil {
		return nil, fmt.Errorf("OIDC verifier initialization failed: %w", oidcErr)
	}

	idToken, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify OIDC token: %w", err)
	}

	var oidcClaims map[string]any
	if err := idToken.Claims(&oidcClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return j.mapOIDCClaims(idToken, oidcClaims)
}

func (j *JWTManager) mapOIDCClaims(idToken *oidc.IDToken, oidcClaims map[string]any) (*JWTClaims, error) {
	// Extract subject identity: upn -> email -> sub
	var subIdentity string
	if upn, ok := oidcClaims["upn"].(string); ok && upn != "" {
		subIdentity = upn
	} else if email, ok := oidcClaims["email"].(string); ok && email != "" {
		// Secure verification checks
		if emailVerified, hasVerification := oidcClaims["email_verified"].(bool); hasVerification && !emailVerified {
			return nil, fmt.Errorf("unverified email claim rejected")
		}
		subIdentity = email
	} else {
		subIdentity = idToken.Subject
	}

	if subIdentity == "" {
		return nil, fmt.Errorf("OIDC token claims lack subject identity")
	}

	// Map configured OIDC permissions (prevents wildcard privilege escalation)
	var permissions []Permission
	if j.oidcPublishPerms != "" {
		for _, pattern := range strings.Split(j.oidcPublishPerms, ",") {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" {
				permissions = append(permissions, Permission{
					Action:          PermissionActionPublish,
					ResourcePattern: pattern,
				})
			}
		}
	}
	if j.oidcEditPerms != "" {
		for _, pattern := range strings.Split(j.oidcEditPerms, ",") {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" {
				permissions = append(permissions, Permission{
					Action:          PermissionActionEdit,
					ResourcePattern: pattern,
				})
			}
		}
	}

	return &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   idToken.Subject,
			Issuer:    idToken.Issuer,
			IssuedAt:  jwt.NewNumericDate(idToken.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(idToken.Expiry),
		},
		AuthMethod:        MethodOIDC,
		AuthMethodSubject: subIdentity,
		Permissions:       permissions,
	}, nil
}

func (j *JWTManager) validateEdDSAToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&JWTClaims{},
		func(_ *jwt.Token) (interface{}, error) { return j.publicKey, nil },
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("failed to parse token: invalid token status")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token: invalid token claims mapping")
	}

	return claims, nil
}

func (j *JWTManager) HasPermission(resource string, action PermissionAction, permissions []Permission) bool {
	for _, perm := range permissions {
		if perm.Action == action && isResourceMatch(resource, perm.ResourcePattern) {
			return true
		}
	}
	return false
}

func isResourceMatch(resource, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*"))
	}
	return resource == pattern
}
