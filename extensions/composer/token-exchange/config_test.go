// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package oauth2te

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/envoyproxy/envoy/source/extensions/dynamic_modules/sdk/go/shared"
	"github.com/envoyproxy/envoy/source/extensions/dynamic_modules/sdk/go/shared/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// baseConfig returns a valid config with all required fields populated.
func baseConfig() tokenExchangeConfig {
	// #nosec G101 -- dummy credentials for a test fixture
	return tokenExchangeConfig{
		Cluster:          "sts_cluster",
		TokenExchangeURL: "sts.example.com/oauth2/token",
		ClientID:         "my-client",
		ClientSecret:     "my-secret",
	}
}

func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func newMockConfigHandle(ctrl *gomock.Controller) *mocks.MockHttpFilterConfigHandle {
	mockHandle := mocks.NewMockHttpFilterConfigHandle(ctrl)
	mockHandle.EXPECT().Log(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockHandle.EXPECT().DefineCounter(gomock.Any()).Return(shared.MetricID(0), shared.MetricsSuccess).AnyTimes()
	mockHandle.EXPECT().DefineCounter(gomock.Any(), gomock.Any()).Return(shared.MetricID(0), shared.MetricsSuccess).AnyTimes()
	return mockHandle
}

func TestConfigFactory(t *testing.T) {
	t.Run("valid minimal config", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		factory := &tokenExchangeHttpFilterConfigFactory{}
		ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, baseConfig()))

		require.NoError(t, err)
		require.NotNil(t, ff)

		tff, ok := ff.(*tokenExchangeFilterFactory)
		require.True(t, ok)
		require.Equal(t, "sts_cluster", tff.config.Cluster)
		require.Equal(t, defaultSubjectTokenType, tff.config.SubjectTokenType)
		require.Equal(t, defaultTimeoutMs, tff.config.TimeoutMs)
		require.Len(t, tff.config.calloutHeaders, 5)
	})

	t.Run("empty config", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		configHandle := newMockConfigHandle(ctrl)
		factory := &tokenExchangeHttpFilterConfigFactory{}
		ff, err := factory.Create(configHandle, []byte{})

		require.NoError(t, err)
		require.NotNil(t, ff)

		httpHandle := newFilterHandleWithoutPerRouteConfig(ctrl)
		filter := ff.Create(httpHandle)
		require.IsType(t, &shared.EmptyHttpFilter{}, filter)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		factory := &tokenExchangeHttpFilterConfigFactory{}
		ff, err := factory.Create(newMockConfigHandle(ctrl), []byte("{bad"))

		require.Error(t, err)
		require.Nil(t, ff)
		require.Contains(t, err.Error(), "failed to parse config")
	})

	t.Run("missing required fields", func(t *testing.T) {
		tests := []struct {
			missing string
			cfg     tokenExchangeConfig
		}{
			{"cluster", tokenExchangeConfig{TokenExchangeURL: "h/t", ClientID: "c", ClientSecret: "s"}},
			{"token_exchange_url", tokenExchangeConfig{Cluster: "c", ClientID: "c", ClientSecret: "s"}},
			{"client_id", tokenExchangeConfig{Cluster: "c", TokenExchangeURL: "h/t", ClientSecret: "s"}},
			{"client_secret", tokenExchangeConfig{Cluster: "c", TokenExchangeURL: "h/t", ClientID: "c"}},
		}
		for _, tt := range tests {
			t.Run(tt.missing, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				factory := &tokenExchangeHttpFilterConfigFactory{}
				ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, tt.cfg))
				require.Error(t, err)
				require.Nil(t, ff)
				require.Contains(t, err.Error(), tt.missing)
			})
		}
	})

	t.Run("resource validation", func(t *testing.T) {
		tests := []struct {
			name      string
			resource  string
			wantErr   bool
			errSubstr string
		}{
			{"not absolute", "not-absolute", true, "absolute URI"},
			{"has fragment", "https://x.com#frag", true, "without fragment"},
			{"valid with query", "https://x.com?q=1", false, ""},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				cfg := baseConfig()
				cfg.Resource = tt.resource

				factory := &tokenExchangeHttpFilterConfigFactory{}
				ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, cfg))
				if tt.wantErr {
					require.Error(t, err)
					require.Nil(t, ff)
					require.Contains(t, err.Error(), tt.errSubstr)
				} else {
					require.NoError(t, err)
					require.NotNil(t, ff)
				}
			})
		}
	})

	t.Run("actor token validation", func(t *testing.T) {
		t.Run("without type", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			cfg := baseConfig()
			cfg.ActorToken = "tok"

			factory := &tokenExchangeHttpFilterConfigFactory{}
			ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, cfg))
			require.Error(t, err)
			require.Nil(t, ff)
			require.Contains(t, err.Error(), "actor_token_type is required")
		})

		t.Run("with type", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			cfg := baseConfig()
			cfg.ActorToken = "tok"
			cfg.ActorTokenType = "urn:ietf:params:oauth:token-type:access_token"

			factory := &tokenExchangeHttpFilterConfigFactory{}
			ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, cfg))
			require.NoError(t, err)
			require.NotNil(t, ff)
		})
	})

	t.Run("stsPostBodyPrefix", func(t *testing.T) {
		cfg, err := parseConfig(marshalJSON(t, baseConfig()))
		require.NoError(t, err)

		// Append a subject token, this is what will happened at request time
		token := "tok&enExample"
		body := cfg.stsPostBodyPrefix + url.QueryEscape(token)

		form, err := url.ParseQuery(body)
		require.NoError(t, err)
		require.Equal(t, grantTypeTokenExchange, form.Get("grant_type"))
		require.Equal(t, defaultSubjectTokenType, form.Get("subject_token_type"))
		require.Equal(t, token, form.Get("subject_token"))
	})

	t.Run("all optional fields", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := baseConfig()
		cfg.SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
		cfg.Resource = "https://api.example.com/v1"
		cfg.Audience = "https://api.example.com"
		cfg.Scope = "read write"
		cfg.RequestedTokenType = "urn:ietf:params:oauth:token-type:access_token"
		cfg.ActorToken = "actor-tok"
		cfg.ActorTokenType = "urn:ietf:params:oauth:token-type:access_token"
		cfg.TimeoutMs = 3000

		factory := &tokenExchangeHttpFilterConfigFactory{}
		ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, cfg))

		require.NoError(t, err)
		require.NotNil(t, ff)
		tff := ff.(*tokenExchangeFilterFactory)
		require.Equal(t, "urn:ietf:params:oauth:token-type:jwt", tff.config.SubjectTokenType)
		require.Equal(t, "https://api.example.com/v1", tff.config.Resource)
		require.Equal(t, "https://api.example.com", tff.config.Audience)
		require.Equal(t, "read write", tff.config.Scope)
		require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", tff.config.RequestedTokenType)
		require.Equal(t, "actor-tok", tff.config.ActorToken)
		require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", tff.config.ActorTokenType)
		require.Equal(t, uint64(3000), tff.config.TimeoutMs)
	})
}

func TestCacheConfig(t *testing.T) {
	t.Run("disabled by default when omitted", func(t *testing.T) {
		cfg, err := parseConfig(marshalJSON(t, baseConfig()))
		require.NoError(t, err)
		require.Nil(t, cfg.Cache)
	})

	t.Run("defaults applied when enabled", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Cache = &cacheConfig{Enabled: true}
		parsed, err := parseConfig(marshalJSON(t, cfg))
		require.NoError(t, err)
		require.NotNil(t, parsed.Cache)
		require.Equal(t, defaultCacheMaxEntries, parsed.Cache.MaxEntries)
		require.Equal(t, defaultCacheTTLSeconds, parsed.Cache.TTLSeconds)
	})

	t.Run("explicit values preserved", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Cache = &cacheConfig{Enabled: true, MaxEntries: 100, TTLSeconds: 60}
		parsed, err := parseConfig(marshalJSON(t, cfg))
		require.NoError(t, err)
		require.Equal(t, 100, parsed.Cache.MaxEntries)
		require.Equal(t, 60, parsed.Cache.TTLSeconds)
	})

	t.Run("not validated when disabled", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Cache = &cacheConfig{Enabled: false, MaxEntries: -5}
		_, err := parseConfig(marshalJSON(t, cfg))
		require.NoError(t, err)
	})

	t.Run("invalid values rejected", func(t *testing.T) {
		tests := []struct {
			name    string
			cache   *cacheConfig
			errPart string
		}{
			{"negative max_entries", &cacheConfig{Enabled: true, MaxEntries: -1}, "max_entries"},
			{"negative ttl", &cacheConfig{Enabled: true, TTLSeconds: -1}, "ttl_seconds"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := baseConfig()
				cfg.Cache = tt.cache
				_, err := parseConfig(marshalJSON(t, cfg))
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errPart)
			})
		}
	})

	t.Run("factory builds cache when enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := baseConfig()
		cfg.Cache = &cacheConfig{Enabled: true}
		factory := &tokenExchangeHttpFilterConfigFactory{}
		ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, cfg))
		require.NoError(t, err)
		tff := ff.(*tokenExchangeFilterFactory)
		require.NotNil(t, tff.cache)
	})

	t.Run("factory has no cache when disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		factory := &tokenExchangeHttpFilterConfigFactory{}
		ff, err := factory.Create(newMockConfigHandle(ctrl), marshalJSON(t, baseConfig()))
		require.NoError(t, err)
		tff := ff.(*tokenExchangeFilterFactory)
		require.Nil(t, tff.cache)
	})
}

func TestParseTokenExchangeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPath string
		wantErr  bool
	}{
		{"host only", "sts.example.com", "", "", true},
		{"path only", "/oauth2/token", "", "", true},
		{"empty", "", "", "", true},
		{"no scheme", "sts.example.com/oauth2/token", "sts.example.com", "/oauth2/token", false},
		{"http", "http://sts.example.com/oauth2/token", "sts.example.com", "/oauth2/token", false},
		{"https", "https://sts.example.com/oauth2/token", "sts.example.com", "/oauth2/token", false},
		{"port", "sts.example.com:8443/oauth2/token", "sts.example.com:8443", "/oauth2/token", false},
		{"port and scheme", "https://sts.example.com:8443/oauth2/token", "sts.example.com:8443", "/oauth2/token", false},
		{"with query", "sts.example.com/oauth2/token?foo=bar", "sts.example.com", "/oauth2/token?foo=bar", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, path, err := parseTokenExchangeURL(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantHost, host)
			require.Equal(t, tt.wantPath, path)
		})
	}
}
