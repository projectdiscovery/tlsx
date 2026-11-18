package main

import (
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

// TestValidateTLSGroupsFlag ensures an explicitly empty -tls-groups value is
// rejected instead of silently running with the default groups.
func TestValidateTLSGroupsFlag(t *testing.T) {
	cases := []struct {
		args    []string
		wantErr bool
	}{
		{args: nil},
		{args: []string{"-tg", "X25519"}},
		{args: []string{"-tls-groups", "X25519,CurveP256"}},
		{args: []string{"-tg", ""}, wantErr: true},
		{args: []string{"-tls-groups", ","}, wantErr: true},
		{args: []string{"-tg", " "}, wantErr: true},
	}
	for _, tc := range cases {
		var groups goflags.StringSlice
		flagSet := goflags.NewFlagSet()
		flagSet.StringSliceVarP(&groups, "tls-groups", "tg", nil, "", goflags.FileCommaSeparatedStringSliceOptions)
		require.NoError(t, flagSet.CommandLine.Parse(tc.args))

		err := validateTLSGroupsFlag(flagSet, groups)
		if tc.wantErr {
			require.Error(t, err, "%q", tc.args)
		} else {
			require.NoError(t, err, "%q", tc.args)
		}
	}
}
