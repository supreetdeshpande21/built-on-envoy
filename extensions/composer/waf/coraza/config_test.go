// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package coraza

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tetratelabs/built-on-envoy/extensions/composer/waf/logger"
)

func TestGetOrCreateSharedWAFFromConfig(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		config := map[string]interface{}{
			"directives": []string{
				"Include @coraza.conf",
				"Include @ftw.conf",
				"Include @crs-setup.conf",
				"Include @owasp_crs/*.conf",
			},
		}

		// Convert map to JSON bytes
		wafConfig, _ := json.Marshal(config)

		waf, mode, _, err := GetOrCreateSharedWAFFromConfig(wafConfig, logger.GetLogger())
		require.NoError(t, err)
		require.NotNil(t, waf)
		// REQUEST_ONLY is the default when no mode is set.
		require.Equal(t, ModeRequestOnly, mode)
	})

	t.Run("explicit mode", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			modeStr  string
			expected WAFMode
		}{
			{"request_only", "REQUEST_ONLY", ModeRequestOnly},
			{"full", "FULL", ModeFull},
			// RESPONSE_ONLY is deprecated but must still parse for backward compatibility.
			{"response_only_deprecated", "RESPONSE_ONLY", ModeResponseOnly},
		} {
			t.Run(tc.name, func(t *testing.T) {
				config := map[string]interface{}{
					"directives": []string{
						"Include @coraza.conf",
						"Include @ftw.conf",
						"Include @crs-setup.conf",
						"Include @owasp_crs/*.conf",
					},
					"mode": tc.modeStr,
				}
				wafConfig, _ := json.Marshal(config)

				waf, mode, _, err := GetOrCreateSharedWAFFromConfig(wafConfig, logger.GetLogger())
				require.NoError(t, err)
				require.NotNil(t, waf)
				require.Equal(t, tc.expected, mode)
			})
		}
	})

	t.Run("request_uri_path_only", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			value    any
			expected bool
		}{
			{"unset", nil, defaultRequestURIPathOnly},
			{"true", true, true},
			{"false", false, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				config := map[string]interface{}{"directives": []string{"Include @coraza.conf"}}
				if tc.value != nil {
					config["request_uri_path_only"] = tc.value
				}
				wafConfig, _ := json.Marshal(config)

				_, _, pathOnly, err := GetOrCreateSharedWAFFromConfig(wafConfig, logger.GetLogger())
				require.NoError(t, err)
				require.Equal(t, tc.expected, pathOnly)
			})
		}
	})

	t.Run("invalid mode", func(t *testing.T) {
		config := map[string]interface{}{
			"directives": []string{"Include @coraza.conf"},
			"mode":       "SIDEWAYS",
		}
		wafConfig, _ := json.Marshal(config)

		waf, _, _, err := GetOrCreateSharedWAFFromConfig(wafConfig, logger.GetLogger())
		require.ErrorContains(t, err, "invalid mode")
		require.Nil(t, waf)
	})

	t.Run("crs_version", func(t *testing.T) {
		directives := []string{
			"Include @coraza.conf",
			"Include @crs-setup.conf",
			"Include @owasp_crs/*.conf",
		}
		get := func(t *testing.T, crsVersion string) *SharedWAF {
			t.Helper()
			config := map[string]interface{}{"directives": directives}
			if crsVersion != "" {
				config["crs_version"] = crsVersion
			}
			wafConfig, _ := json.Marshal(config)
			waf, _, _, err := GetOrCreateSharedWAFFromConfig(wafConfig, logger.GetLogger())
			require.NoError(t, err)
			return waf
		}

		// Keep the WAFs reachable, so that the shared ones are not collected mid-test.
		defaultWAF, lts, latest := get(t, ""), get(t, "lts"), get(t, "latest")
		// The default is the LTS release.
		require.Same(t, defaultWAF, lts)
		// Same directives against another CRS version must not share the WAF.
		require.NotSame(t, lts, latest)
		require.Same(t, latest, get(t, "latest"))
	})

	t.Run("invalid crs_version", func(t *testing.T) {
		// Only the aliases are accepted: the embedded versions are not exposed.
		for _, v := range []string{"4.30.0", "4.25.2", "4", "4.25", "4.30", "4.26.0", "9.9.9", "v4.30.0", "LTS", "stable"} {
			t.Run(v, func(t *testing.T) {
				config := map[string]interface{}{
					"directives":  []string{"Include @coraza.conf"},
					"crs_version": v,
				}
				wafConfig, _ := json.Marshal(config)

				waf, _, _, err := GetOrCreateSharedWAFFromConfig(wafConfig, logger.GetLogger())
				require.EqualError(t, err, fmt.Sprintf("unsupported crs_version %q, supported values are: latest (4.30.0), lts (4.25.2)", v))
				require.Nil(t, waf)
			})
		}
	})

	t.Run("error", func(t *testing.T) {
		config := map[string]interface{}{
			"directives": []string{
				"foo",
			},
		}
		// Convert map to JSON bytes
		wafConfig, _ := json.Marshal(config)

		waf, _, _, err := GetOrCreateSharedWAFFromConfig(wafConfig, logger.GetLogger())
		require.ErrorContains(t, err, "failed to create WAF")
		require.Nil(t, waf)
	})
}

func TestParseConfigCRSVersion(t *testing.T) {
	set := mustCRSBundles(t)
	byVersion := func(v string) *crsBundle {
		b := set.byVersion(v)
		require.NotNil(t, b, v)
		return b
	}
	for _, tc := range []struct {
		version  string
		expected *crsBundle
	}{
		// The CRS LTS release is the default.
		{version: "", expected: byVersion("4.25.2")},
		{version: "latest", expected: byVersion("4.30.0")},
		{version: "lts", expected: byVersion("4.25.2")},
	} {
		t.Run(tc.version, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"directives": []string{"SecRuleEngine On"}, "crs_version": tc.version})
			cfg, err := parseConfig(raw, logger.GetLogger())
			require.NoError(t, err)
			require.Same(t, tc.expected, cfg.CRS)
		})
	}
}
