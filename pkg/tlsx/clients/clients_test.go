package clients

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsMisMatchedCert(t *testing.T) {
	type args struct {
		host  string
		names []string
	}

	tests := []struct {
		args args
		want bool
	}{
		{args{host: "target.com", names: []string{"target.com"}}, false},
		{args{host: "target.com", names: []string{"other-target.com", "target.com"}}, false},
		{args{host: "subdomain.target.com", names: []string{"*.target.com", "other-target.com"}}, false},
		{args{host: "foo.example.net", names: []string{"*.example.net"}}, false},
		{args{host: "aaábçdë.ext", names: []string{"AaÁBçdë.ext"}}, false},

		{args{host: "baz1.example.net", names: []string{"baz*.example.net"}}, false},
		{args{host: "foobaz.example.net", names: []string{"*baz.example.net"}}, false},
		{args{host: "buzz.example.net", names: []string{"b*z.example.net"}}, false},

		// negative scenarios
		{args{host: "bar.foo.example.net", names: []string{"*.example.net"}}, true},
		{args{host: "target.com", names: []string{"other-target.com"}}, true},
		{args{host: "target.com", names: []string{"*-target.com"}}, true},
		{args{host: "target.com", names: []string{"target.*m"}}, true},

		{args{host: "*.target.com", names: []string{"other-target.com", "target.com", "subdomain.target.*"}}, true},
		{args{host: "*.com", names: []string{"other-target.com", "subdomain.target.com"}}, true},
		{args{host: "subdomain.target.com", names: []string{"other-target.com", "subdomain.target.*"}}, true},
		{args{host: "subdomain.target.com", names: []string{"subdomain.*.com", "other-target.com"}}, true},
	}

	for _, test := range tests {
		testName := fmt.Sprintf("(%s vs [%s])", test.args.host, strings.Join(test.args.names, ","))
		t.Run(testName, func(t *testing.T) {
			got := IsMisMatchedCert(test.args.host, test.args.names)
			assert.Equal(t, test.want, got)
		})
	}
}

func Test_matchWildCardToken(t *testing.T) {
	type args struct {
		nameToken string
		hostToken string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{

		{args: args{nameToken: "b*z", hostToken: "buzz"}, want: true},
		{args: args{nameToken: "*buzz", hostToken: "foobuzz"}, want: true},
		{args: args{nameToken: "foo*", hostToken: "foobuzz"}, want: true},
		{args: args{nameToken: "foo*", hostToken: "buzz"}, want: false},
		{args: args{nameToken: "*buzz", hostToken: "foo"}, want: false},
		{args: args{nameToken: "*", hostToken: "foo"}, want: true},
		{args: args{nameToken: "subdomain", hostToken: "subdomain"}, want: true},
	}
	for i, tt := range tests {
		testName := fmt.Sprintf("wildcard%d", i)
		t.Run(testName, func(t *testing.T) {
			got := matchWildCardToken(tt.args.nameToken, tt.args.hostToken)
			assert.Equal(t, tt.want, got)
		})
	}
}
