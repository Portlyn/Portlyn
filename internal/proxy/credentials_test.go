package proxy

import (
	"net/http"
	"testing"
)

func TestStripPortlynCookies(t *testing.T) {
	headers := http.Header{}
	headers.Add("Cookie", "portlyn_session=abc; app_session=keep; portlyn_route_access_4=x")
	headers.Add("Cookie", "Portlyn_Refresh=r; portlyn_csrf=c; theme=dark")

	stripPortlynCookies(headers)

	if got := headers.Values("Cookie"); len(got) != 1 || got[0] != "app_session=keep; theme=dark" {
		t.Fatalf("unexpected cookies after strip: %q", got)
	}
}

func TestStripPortlynCookiesDropsHeaderWhenOnlyPortlynCookies(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cookie", "portlyn_session=abc")

	stripPortlynCookies(headers)

	if _, ok := headers["Cookie"]; ok {
		t.Fatalf("expected cookie header to be removed, got %q", headers.Values("Cookie"))
	}
}

func TestStripPortlynCookiesLeavesForeignCookiesUntouched(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cookie", "a=1;b=2")

	stripPortlynCookies(headers)

	if got := headers.Get("Cookie"); got != "a=1;b=2" {
		t.Fatalf("expected cookie header to stay as sent, got %q", got)
	}
}
