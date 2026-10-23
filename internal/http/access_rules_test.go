package http

import (
	"testing"

	"github.com/go-playground/validator/v10"

	"portlyn/internal/domain"
)

func TestValidateAccessRules(t *testing.T) {
	rules := toAccessRules([]accessRuleRequest{
		{Name: " office ", Action: "ALLOW", Sources: []string{"8.8.8.0/24", " !8.8.8.8 ", ""}, Paths: []string{"/pub"}},
	})
	if rules[0].Name != "office" || rules[0].Action != domain.AccessRuleAllow || len(rules[0].Sources) != 2 {
		t.Fatalf("unexpected normalized rule %+v", rules[0])
	}
	if err := validateAccessRules(rules); err != nil {
		t.Fatalf("expected valid rules, got %v", err)
	}

	bad := []domain.AccessRuleList{
		{{Action: domain.AccessRuleDeny, Sources: []string{"10.0.0.0/33"}}},
		{{Action: domain.AccessRuleDeny, Paths: []string{"/a?b=1"}}},
	}
	for _, item := range bad {
		if err := validateAccessRules(item); err == nil {
			t.Fatalf("expected %+v to be rejected", item)
		}
	}
}

func TestAccessRuleRequestValidation(t *testing.T) {
	v := validator.New(validator.WithRequiredStructEnabled())
	req := updateServiceRequest{AccessRules: &[]accessRuleRequest{{Action: "block"}}}
	if err := v.Struct(req); err == nil {
		t.Fatal("expected unknown action to fail validation")
	}
}
