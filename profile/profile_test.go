package profile

import (
	"strings"
	"testing"
)

func TestQuoteForbidden(t *testing.T) {
	forbidden := []string{";", "="}
	s := ";="
	quoted := QuoteForbidden(forbidden, s)
	if len(quoted) < len(s) {
		t.Fail()
	}
}

func TestNew(t *testing.T) {
	bad := "foo@bar.com&admin=true"
	good := "foo@bar.com"
	expected := "email=foo@bar.com&uid=1&role=user"

	profile := New(bad)
	split := strings.Split(profile, "&")
	if len(split) != 3 {
		t.Error("&, = should be stripped from email addresses before creating a profile")
	}

	profile = New(good)
	if profile != expected {
		t.Errorf("expected %s, got %s", expected, profile)
	}
}
