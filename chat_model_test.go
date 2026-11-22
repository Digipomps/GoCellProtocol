// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"unicode/utf8"
)

// The chat model rules against the Swift scenario fixtures (chat-model-v1).

type chatModelFixture struct {
	Constants struct {
		ContextLimit       int      `json:"contextLimit"`
		AnswerLimitScalars int      `json:"answerLimitScalars"`
		AskLifetimeSeconds int      `json:"askLifetimeSeconds"`
		MentionTokens      []string `json:"mentionTokens"`
	} `json:"constants"`
	LedgerScenarios []struct {
		Name  string `json:"name"`
		Steps []struct {
			Event    string         `json:"event"`
			Member   string         `json:"member"`
			External bool           `json:"external"`
			At       string         `json:"at"`
			Members  []string       `json:"members"`
			Expect   map[string]any `json:"expect"`
		} `json:"steps"`
	} `json:"ledgerScenarios"`
	MentionCases []struct {
		Text   string `json:"text"`
		Expect bool   `json:"expect"`
	} `json:"mentionCases"`
	ContextCases []struct {
		Name     string `json:"name"`
		Messages []struct {
			ID        string `json:"id"`
			CreatedAt string `json:"createdAt"`
		} `json:"messages"`
		ActivatedAt string   `json:"activatedAt"`
		QuestionID  string   `json:"questionID"`
		Limit       int      `json:"limit"`
		Expect      []string `json:"expect"`
	} `json:"contextCases"`
	SanitizeCases []struct {
		Name              string `json:"name"`
		Text              string `json:"text"`
		Expect            string `json:"expect"`
		ExpectScalarCount int    `json:"expectScalarCount"`
	} `json:"sanitizeCases"`
}

func loadChatModelFixture(t *testing.T) chatModelFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/chat-model-v1/scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture chatModelFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func asJSONValue(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestChatModelConstantsMatchSwift(t *testing.T) {
	c := loadChatModelFixture(t).Constants
	if c.ContextLimit != ChatModelContextLimit || c.AnswerLimitScalars != ChatModelAnswerLimitScalars ||
		c.AskLifetimeSeconds != ChatModelAskLifetimeSeconds || !reflect.DeepEqual(c.MentionTokens, ChatModelMentionTokens) {
		t.Fatalf("constants differ: %+v", c)
	}
}

func TestChatModelLedgerScenarios(t *testing.T) {
	for _, scenario := range loadChatModelFixture(t).LedgerScenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			ledger := NewChatModelConsentLedger()
			for index, step := range scenario.Steps {
				var err error
				switch step.Event {
				case "propose":
					err = ledger.Propose("6F1C2B0A-0000-4000-8000-0000000A0DE1", "Modell", step.Member, step.External, step.At, step.Members)
				case "consent":
					err = ledger.Consent(step.Member, step.External, step.At, step.Members)
				case "decline":
					err = ledger.Decline(step.Member, step.At, step.Members)
				case "remove":
					err = ledger.Remove(step.Member, step.At, step.Members)
				case "membersChanged":
					ledger.MembersChanged(step.Members, step.At)
				default:
					t.Fatalf("unknown event %s", step.Event)
				}
				var refusal any
				if r, ok := err.(*ChatModelRefusal); ok {
					refusal = r.Code
				}
				awaiting := map[string]any{}
				for _, m := range step.Members {
					awaiting[m] = ledger.AwaitingAnswer(m, step.Members)
				}
				got := map[string]any{
					"refusal": refusal, "status": ledger.Status, "activatedAt": orNilString(ledger.ActivatedAt),
					"modelConsentHolds": ledger.ModelConsentHolds(step.Members),
					"externalAllowed":   ledger.ExternalAllowed(step.Members),
					"consentedMembers":  ledger.ConsentedMembers(step.Members),
					"awaitingAnswer":    awaiting,
				}
				if want := asJSONValue(t, step.Expect); !reflect.DeepEqual(asJSONValue(t, got), want) {
					t.Fatalf("step %d: got %v want %v", index, got, want)
				}
			}
		})
	}
}

func TestChatModelMentions(t *testing.T) {
	for _, item := range loadChatModelFixture(t).MentionCases {
		if got := IsAddressedToModel(item.Text); got != item.Expect {
			t.Errorf("%q: got %v want %v", item.Text, got, item.Expect)
		}
	}
}

func TestChatModelContextWindow(t *testing.T) {
	for _, item := range loadChatModelFixture(t).ContextCases {
		stamps := []ChatModelMessageStamp{}
		for _, m := range item.Messages {
			stamps = append(stamps, ChatModelMessageStamp{ID: m.ID, CreatedAt: m.CreatedAt})
		}
		got := ChatModelContextMessageIDs(stamps, item.ActivatedAt, item.QuestionID, item.Limit)
		if !reflect.DeepEqual(got, item.Expect) {
			t.Errorf("%s: got %v want %v", item.Name, got, item.Expect)
		}
	}
}

func TestChatModelSanitize(t *testing.T) {
	for _, item := range loadChatModelFixture(t).SanitizeCases {
		got := SanitizeChatModelAnswer(item.Text)
		if got != item.Expect || utf8.RuneCountInString(got) != item.ExpectScalarCount {
			t.Errorf("%s: got %q (%d) want %q (%d)", item.Name, got, utf8.RuneCountInString(got), item.Expect, item.ExpectScalarCount)
		}
	}
}
