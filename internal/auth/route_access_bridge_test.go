package auth

import (
	"strings"
	"testing"
)

func TestIssueAndParseRouteAccessBridgeToken(t *testing.T) {
	svc := &Service{
		issuer:              "portlyn-test",
		sessionBridgeSecret: []byte("bridge-secret-needs-32-bytes-of-data!!"),
	}
	token, err := svc.IssueRouteAccessBridgeToken(42, "gitea.example.com", "pin", "", "https://gitea.example.com/issues")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(token, ".") {
		t.Fatalf("expected JWT, got %s", token)
	}
	claims, err := svc.ParseRouteAccessBridgeToken(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.ServiceID != 42 {
		t.Fatalf("service_id: got %d", claims.ServiceID)
	}
	if claims.Host != "gitea.example.com" {
		t.Fatalf("host: got %s", claims.Host)
	}
	if claims.Method != "pin" {
		t.Fatalf("method: got %s", claims.Method)
	}
	if claims.ReturnTo != "https://gitea.example.com/issues" {
		t.Fatalf("return_to: got %s", claims.ReturnTo)
	}
}

func TestRouteAccessBridgeRejectsZeroServiceID(t *testing.T) {
	svc := &Service{
		issuer:              "portlyn-test",
		sessionBridgeSecret: []byte("bridge-secret-needs-32-bytes-of-data!!"),
	}
	if _, err := svc.IssueRouteAccessBridgeToken(0, "gitea.example.com", "pin", "", ""); err == nil {
		t.Fatal("expected error for zero service id")
	}
	if _, err := svc.IssueRouteAccessBridgeToken(1, "  ", "pin", "", ""); err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestRouteAccessBridgeNormalizesHostPort(t *testing.T) {
	svc := &Service{
		issuer:              "portlyn-test",
		sessionBridgeSecret: []byte("bridge-secret-needs-32-bytes-of-data!!"),
	}
	token, err := svc.IssueRouteAccessBridgeToken(1, "GitEa.Example.com:8443", "pin", "", "")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := svc.ParseRouteAccessBridgeToken(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.Host != "gitea.example.com" {
		t.Fatalf("expected normalized host, got %s", claims.Host)
	}
}
