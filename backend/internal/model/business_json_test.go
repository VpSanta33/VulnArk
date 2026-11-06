package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBusinessJSONScanners(t *testing.T) {
	cases := []struct {
		name    string
		value   interface{}
		want    map[string]interface{}
		wantErr bool
	}{
		{name: "nil", value: nil, want: map[string]interface{}{}},
		{name: "string", value: `{"name":"server","severity":2}`, want: map[string]interface{}{"name": "server", "severity": float64(2)}},
		{name: "bytes", value: []byte(`{"name":"server"}`), want: map[string]interface{}{"name": "server"}},
		{name: "empty string object", value: "{}", want: map[string]interface{}{}},
		{name: "empty bytes object", value: []byte("{}"), want: map[string]interface{}{}},
		{name: "invalid string JSON", value: "{", wantErr: true},
		{name: "invalid bytes JSON", value: []byte("{"), wantErr: true},
		{name: "unsupported type", value: int64(1), wantErr: true},
	}
	for _, scanner := range []string{"KBMetadata", "AssignmentConditions"} {
		t.Run(scanner, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var got map[string]interface{}
					var err error
					if scanner == "KBMetadata" {
						var metadata KBMetadata
						err = metadata.Scan(tc.value)
						got = map[string]interface{}(metadata)
					} else {
						var conditions AssignmentConditions
						err = conditions.Scan(tc.value)
						got = map[string]interface{}(conditions)
					}
					if tc.wantErr {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					require.Equal(t, tc.want, got)
				})
			}
		})
	}
}

func TestEmptyBusinessJSONValueRoundTrip(t *testing.T) {
	var metadata KBMetadata
	value, err := metadata.Value()
	require.NoError(t, err)
	require.NoError(t, metadata.Scan(value))
	require.NotNil(t, metadata)
	require.Empty(t, metadata)

	var conditions AssignmentConditions
	value, err = conditions.Value()
	require.NoError(t, err)
	require.NoError(t, conditions.Scan(value))
	require.NotNil(t, conditions)
	require.Empty(t, conditions)
}
