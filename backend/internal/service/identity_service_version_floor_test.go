package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/stretchr/testify/require"
)

type fingerprintCacheStub struct {
	identityCacheStub
	fp     *Fingerprint
	writes int
}

func (s *fingerprintCacheStub) GetFingerprint(_ context.Context, _ int64) (*Fingerprint, error) {
	return s.fp, nil
}

func (s *fingerprintCacheStub) SetFingerprint(_ context.Context, _ int64, fp *Fingerprint) error {
	s.fp = fp
	s.writes++
	return nil
}

func currentCLIUserAgent() string {
	return "claude-cli/" + claude.CLICurrentVersion + " (external, cli)"
}

func TestGetOrCreateFingerprint_RaisesStaleCachedVersion(t *testing.T) {
	cache := &fingerprintCacheStub{fp: &Fingerprint{
		ClientID:                "client-1",
		UserAgent:               "claude-cli/2.1.92 (external, cli)",
		StainlessPackageVersion: "0.70.0",
		StainlessOS:             "MacOS",
		StainlessArch:           "x64",
		StainlessRuntimeVersion: "v24.13.0",
	}}
	svc := NewIdentityService(cache)

	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.92 (external, cli)")
	fp, err := svc.GetOrCreateFingerprint(context.Background(), 1, headers)
	require.NoError(t, err)

	require.Equal(t, currentCLIUserAgent(), fp.UserAgent)
	require.Equal(t, defaultFingerprint.StainlessPackageVersion, fp.StainlessPackageVersion)
	require.Equal(t, defaultFingerprint.StainlessRuntimeVersion, fp.StainlessRuntimeVersion)
	require.Equal(t, "MacOS", fp.StainlessOS, "机器特征应保留")
	require.Equal(t, "x64", fp.StainlessArch, "机器特征应保留")
	require.Equal(t, "client-1", fp.ClientID)
	require.Equal(t, 1, cache.writes)
}

func TestGetOrCreateFingerprint_RaisesStaleClientOnCreate(t *testing.T) {
	svc := NewIdentityService(&fingerprintCacheStub{})

	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.92 (external, cli)")
	fp, err := svc.GetOrCreateFingerprint(context.Background(), 1, headers)
	require.NoError(t, err)
	require.Equal(t, currentCLIUserAgent(), fp.UserAgent)
}

func TestGetOrCreateFingerprint_KeepsNewerClientVersion(t *testing.T) {
	svc := NewIdentityService(&fingerprintCacheStub{})

	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/9.0.0 (external, cli)")
	headers.Set("X-Stainless-Package-Version", "1.2.3")
	fp, err := svc.GetOrCreateFingerprint(context.Background(), 1, headers)
	require.NoError(t, err)
	require.Equal(t, "claude-cli/9.0.0 (external, cli)", fp.UserAgent)
	require.Equal(t, "1.2.3", fp.StainlessPackageVersion)
}

func TestFloorFingerprintVersion_IgnoresNonCLIUserAgent(t *testing.T) {
	fp := &Fingerprint{UserAgent: "python-requests/2.31.0"}
	require.False(t, floorFingerprintVersion(fp))
	require.Equal(t, "python-requests/2.31.0", fp.UserAgent)
}
