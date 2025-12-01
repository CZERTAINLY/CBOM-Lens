package model_test

import (
	"encoding/json"
	"net"
	"net/url"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURL_UnmarshalText(t *testing.T) {
	type then struct {
		expectedURL string
		err         bool
	}
	cases := []struct {
		scenario string
		given    string
		then     then
	}{
		{
			scenario: "valid_http_url",
			given:    "http://example.com",
			then:     then{expectedURL: "http://example.com"},
		},
		{
			scenario: "valid_https_url",
			given:    "https://example.com/path?query=value",
			then:     then{expectedURL: "https://example.com/path?query=value"},
		},
		{
			scenario: "valid_url_with_port",
			given:    "http://example.com:8080",
			then:     then{expectedURL: "http://example.com:8080"},
		},
		{
			scenario: "valid_url_with_fragment",
			given:    "https://example.com#section",
			then:     then{expectedURL: "https://example.com#section"},
		},
		{
			scenario: "relative_url",
			given:    "/path/to/resource",
			then:     then{expectedURL: "/path/to/resource"},
		},
		{
			scenario: "empty_string",
			given:    "",
			then:     then{expectedURL: ""},
		},
		{
			scenario: "invalid_url_with_spaces",
			given:    "http://exa mple.com",
			then:     then{err: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			var u model.URL
			err := u.UnmarshalText([]byte(tc.given))

			if tc.then.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.then.expectedURL, u.String())
			}
		})
	}
}

func TestURL_MarshalText(t *testing.T) {
	type then struct {
		expected string
	}
	cases := []struct {
		scenario string
		given    *url.URL
		then     then
	}{
		{
			scenario: "valid_url",
			given:    mustParseURL("http://example.com"),
			then:     then{expected: "http://example.com"},
		},
		{
			scenario: "url_with_query",
			given:    mustParseURL("https://example.com/path?key=value"),
			then:     then{expected: "https://example.com/path?key=value"},
		},
		{
			scenario: "url_with_fragment",
			given:    mustParseURL("https://example.com#section"),
			then:     then{expected: "https://example.com#section"},
		},
		{
			scenario: "nil_url",
			given:    nil,
			then:     then{expected: ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			u := model.URL{URL: tc.given}
			result, err := u.MarshalText()

			require.NoError(t, err)
			assert.Equal(t, tc.then.expected, string(result))
		})
	}
}

func TestURL_JSON_RoundTrip(t *testing.T) {
	type then struct {
		expectedURL string
	}
	cases := []struct {
		scenario string
		given    string
		then     then
	}{
		{
			scenario: "simple_url",
			given:    `{"url":"http://example.com"}`,
			then:     then{expectedURL: "http://example.com"},
		},
		{
			scenario: "complex_url",
			given:    `{"url":"https://example.com:8080/path?q=test#frag"}`,
			then:     then{expectedURL: "https://example.com:8080/path?q=test#frag"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			var data struct {
				URL model.URL `json:"url"`
			}

			err := json.Unmarshal([]byte(tc.given), &data)
			require.NoError(t, err)
			assert.Equal(t, tc.then.expectedURL, data.URL.String())

			// Marshal back and verify
			result, err := json.Marshal(data)
			require.NoError(t, err)
			assert.JSONEq(t, tc.given, string(result))
		})
	}
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

func TestTCPAddr_UnmarshalText(t *testing.T) {
	testCases := []struct {
		scenario string
		given    string
		setenv   func(t *testing.T)
		then     func(t *testing.T, addr *model.TCPAddr, err error)
	}{
		{
			scenario: "valid IPv4 address with port",
			given:    "192.168.1.1:8080",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.NoError(t, err)
				require.NotNil(t, addr.AsTCPAddr())
				require.Equal(t, "192.168.1.1", addr.IP.String())
				require.Equal(t, 8080, addr.Port)
			},
		},
		{
			scenario: "valid IPv6 address with port",
			given:    "[::1]:8080",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.NoError(t, err)
				require.NotNil(t, addr.AsTCPAddr())
				require.True(t, addr.IP.IsLoopback())
				require.Equal(t, 8080, addr.Port)
			},
		},
		{
			scenario: "valid hostname with port",
			given:    "localhost:3000",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.NoError(t, err)
				require.NotNil(t, addr.AsTCPAddr())
				require.Equal(t, 3000, addr.Port)
			},
		},
		{
			scenario: "valid address with port 0",
			given:    "0.0.0.0:0",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.NoError(t, err)
				require.NotNil(t, addr.AsTCPAddr())
				require.Equal(t, 0, addr.Port)
			},
		},
		{
			scenario: "environment variable expansion",
			given:    "${TEST_HOST}:${TEST_PORT}",
			setenv: func(t *testing.T) {
				t.Setenv("TEST_HOST", "127.0.0.1")
				t.Setenv("TEST_PORT", "9000")
			},
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.NoError(t, err)
				require.NotNil(t, addr.AsTCPAddr())
				require.Equal(t, "127.0.0.1", addr.IP.String())
				require.Equal(t, 9000, addr.Port)
			},
		},
		{
			scenario: "empty string",
			given:    "",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "can't be empty")
			},
		},
		{
			scenario: "invalid format - missing port",
			given:    "192.168.1.1",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.Error(t, err)
			},
		},
		{
			scenario: "invalid format - invalid port",
			given:    "192.168.1.1:invalid",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.Error(t, err)
			},
		},
		{
			scenario: "invalid format - port out of range",
			given:    "192.168.1.1:99999",
			then: func(t *testing.T, addr *model.TCPAddr, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			addr := &model.TCPAddr{}
			if tc.setenv != nil {
				tc.setenv(t)
			}
			err := addr.UnmarshalText([]byte(tc.given))
			tc.then(t, addr, err)
		})
	}
}

func TestTCPAddr_MarshalText(t *testing.T) {
	testCases := []struct {
		scenario string
		given    *model.TCPAddr
		then     func(t *testing.T, text []byte, err error)
	}{
		{
			scenario: "valid TCP address",
			given: &model.TCPAddr{
				TCPAddr: &net.TCPAddr{
					IP:   net.ParseIP("192.168.1.1"),
					Port: 8080,
				},
			},
			then: func(t *testing.T, text []byte, err error) {
				require.NoError(t, err)
				require.Equal(t, "192.168.1.1:8080", string(text))
			},
		},
		{
			scenario: "nil TCP address",
			given:    &model.TCPAddr{},
			then: func(t *testing.T, text []byte, err error) {
				require.NoError(t, err)
				require.Empty(t, text)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			text, err := tc.given.MarshalText()
			tc.then(t, text, err)
		})
	}
}

func TestTCPAddr_JSONRoundTrip(t *testing.T) {
	testCases := []struct {
		scenario     string
		given        string
		expectedJSON string
	}{
		{
			scenario:     "IPv4 address with port",
			given:        "192.168.1.1:8080",
			expectedJSON: `"192.168.1.1:8080"`,
		},
		{
			scenario:     "localhost with port",
			given:        "127.0.0.1:3000",
			expectedJSON: `"127.0.0.1:3000"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			addr := &model.TCPAddr{}
			err := addr.UnmarshalText([]byte(tc.given))
			require.NoError(t, err)

			marshaled, err := json.Marshal(addr)
			require.NoError(t, err)
			require.JSONEq(t, tc.expectedJSON, string(marshaled))

			var unmarshaled model.TCPAddr
			err = json.Unmarshal(marshaled, &unmarshaled)
			require.NoError(t, err)
			require.Equal(t, addr.IP.String(), unmarshaled.IP.String())
			require.Equal(t, addr.Port, unmarshaled.Port)
		})
	}
}

func TestURL_Clone(t *testing.T) {
	t.Run("clone nil URL", func(t *testing.T) {
		original := model.URL{}
		cloned := original.Clone()

		require.Nil(t, cloned.URL)
		require.Equal(t, original, cloned)
	})

	t.Run("clone simple URL", func(t *testing.T) {
		original := model.URL{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v1",
			},
		}
		cloned := original.Clone()

		require.NotNil(t, cloned.URL)
		require.Equal(t, original.Scheme, cloned.Scheme)
		require.Equal(t, original.Host, cloned.Host)
		require.Equal(t, original.Path, cloned.Path)
		require.NotSame(t, original.URL, cloned.URL)
	})

	t.Run("clone URL with all fields", func(t *testing.T) {
		original := model.URL{
			URL: &url.URL{
				Scheme:      "https",
				Opaque:      "opaque",
				Host:        "example.com:8080",
				Path:        "/path/to/resource",
				RawPath:     "/path%2Fto%2Fresource",
				RawQuery:    "key=value&foo=bar",
				Fragment:    "section",
				RawFragment: "section%20one",
			},
		}
		cloned := original.Clone()

		require.NotNil(t, cloned.URL)
		require.Equal(t, original.Scheme, cloned.Scheme)
		require.Equal(t, original.Opaque, cloned.Opaque)
		require.Equal(t, original.Host, cloned.Host)
		require.Equal(t, original.Path, cloned.Path)
		require.Equal(t, original.RawPath, cloned.RawPath)
		require.Equal(t, original.RawQuery, cloned.RawQuery)
		require.Equal(t, original.Fragment, cloned.Fragment)
		require.Equal(t, original.RawFragment, cloned.RawFragment)
		require.NotSame(t, original.URL, cloned.URL)
	})

	t.Run("clone URL with user info without password", func(t *testing.T) {
		original := model.URL{
			URL: &url.URL{
				Scheme: "https",
				User:   url.User("username"),
				Host:   "example.com",
			},
		}
		cloned := original.Clone()

		require.NotNil(t, cloned.User)
		require.Equal(t, "username", cloned.User.Username())
		_, hasPassword := cloned.User.Password()
		require.False(t, hasPassword)
		require.NotSame(t, original.User, cloned.User)
	})

	t.Run("clone URL with user info with password", func(t *testing.T) {
		original := model.URL{
			URL: &url.URL{
				Scheme: "https",
				User:   url.UserPassword("username", "secret"),
				Host:   "example.com",
			},
		}
		cloned := original.Clone()

		require.NotNil(t, cloned.User)
		require.Equal(t, "username", cloned.User.Username())
		password, hasPassword := cloned.User.Password()
		require.True(t, hasPassword)
		require.Equal(t, "secret", password)
		require.NotSame(t, original.User, cloned.User)
	})

	t.Run("modifications to clone do not affect original", func(t *testing.T) {
		original := model.URL{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/original",
			},
		}
		cloned := original.Clone()
		cloned.Path = "/modified"

		require.Equal(t, "/original", original.Path)
		require.Equal(t, "/modified", cloned.Path)
	})
}
