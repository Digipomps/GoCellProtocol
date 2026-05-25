// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"encoding/json"
	"fmt"
	"strings"
)

var SupportedSkeletonElements = map[string]struct{}{
	"List":            {},
	"Object":          {},
	"Spacer":          {},
	"Image":           {},
	"Text":            {},
	"AttachmentField": {},
	"FileUpload":      {},
	"TextField":       {},
	"TextArea":        {},
	"HStack":          {},
	"VStack":          {},
	"Reference":       {},
	"Button":          {},
	"Divider":         {},
	"ScrollView":      {},
	"Section":         {},
	"Tabs":            {},
	"ZStack":          {},
	"Grid":            {},
	"Toggle":          {},
	"Picker":          {},
	"Visualization":   {},
}

type SkeletonElement struct {
	Kind    string
	Payload any
}

func NewSkeletonElement(kind string, payload any) (SkeletonElement, error) {
	if _, ok := SupportedSkeletonElements[kind]; !ok {
		return SkeletonElement{}, fmt.Errorf("unsupported skeleton element %q", kind)
	}
	return SkeletonElement{Kind: kind, Payload: NormalizeJSON(payload)}, nil
}

func (e SkeletonElement) MarshalJSON() ([]byte, error) {
	if _, ok := SupportedSkeletonElements[e.Kind]; !ok {
		return nil, fmt.Errorf("unsupported skeleton element %q", e.Kind)
	}
	return json.Marshal(map[string]any{e.Kind: NormalizeJSON(e.Payload)})
}

func (e *SkeletonElement) UnmarshalJSON(data []byte) error {
	var payload map[string]any
	if err := DecodeJSON(data, &payload); err != nil {
		return err
	}
	if len(payload) == 1 {
		for kind, value := range payload {
			if _, ok := SupportedSkeletonElements[kind]; !ok {
				return fmt.Errorf("unsupported skeleton element %q", kind)
			}
			e.Kind = kind
			e.Payload = NormalizeJSON(value)
			return nil
		}
	}
	if _, ok := payload["elements"]; ok {
		e.Kind = "Object"
		e.Payload = NormalizeJSON(payload)
		return nil
	}
	return fmt.Errorf("unsupported skeleton element shape")
}

func (e SkeletonElement) Keypaths() []string {
	seen := map[string]struct{}{}
	var walk func(any)
	walk = func(node any) {
		switch v := NormalizeJSON(node).(type) {
		case map[string]any:
			for key, value := range v {
				lower := strings.ToLower(key)
				if key == "keypath" || strings.HasSuffix(lower, "keypath") {
					if s, ok := value.(string); ok && s != "" {
						seen[s] = struct{}{}
					}
				}
				walk(value)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(e.Payload)
	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	return SortedStrings(out)
}

type CellConfigurationDiscoveryLocalization struct {
	Purpose            string   `json:"purpose,omitempty"`
	PurposeDescription string   `json:"purposeDescription,omitempty"`
	Interests          []string `json:"interests"`
}

type CellConfigurationDiscovery struct {
	SourceCellEndpoint string                                            `json:"sourceCellEndpoint,omitempty"`
	SourceCellName     string                                            `json:"sourceCellName,omitempty"`
	Purpose            string                                            `json:"purpose,omitempty"`
	PurposeDescription string                                            `json:"purposeDescription,omitempty"`
	Interests          []string                                          `json:"interests"`
	PurposeRefs        []string                                          `json:"purposeRefs,omitempty"`
	InterestRefs       []string                                          `json:"interestRefs,omitempty"`
	MenuSlots          []string                                          `json:"menuSlots"`
	LocalizedText      map[string]CellConfigurationDiscoveryLocalization `json:"localizedText,omitempty"`
}

func (d *CellConfigurationDiscovery) Normalize() {
	d.PurposeRefs = SortedStrings(d.PurposeRefs)
	d.InterestRefs = SortedStrings(d.InterestRefs)
	if d.Interests == nil {
		d.Interests = []string{}
	}
	if d.MenuSlots == nil {
		d.MenuSlots = []string{}
	}
	if d.LocalizedText == nil {
		d.LocalizedText = map[string]CellConfigurationDiscoveryLocalization{}
	}
}

func (d *CellConfigurationDiscovery) UnmarshalJSON(data []byte) error {
	type alias CellConfigurationDiscovery
	var a alias
	if err := DecodeJSON(data, &a); err != nil {
		return err
	}
	*d = CellConfigurationDiscovery(a)
	d.Normalize()
	return nil
}

type CellReference struct {
	Endpoint         string          `json:"endpoint"`
	SubscribeFeed    bool            `json:"subscribeFeed"`
	Label            string          `json:"label"`
	Subscriptions    []CellReference `json:"subscriptions"`
	SetKeysAndValues []KeyValue      `json:"setKeysAndValues"`
}

func NewCellReference(endpoint, label string) CellReference {
	return CellReference{
		Endpoint:      endpoint,
		Label:         label,
		SubscribeFeed: true,
		Subscriptions: []CellReference{},
	}
}

func (r CellReference) ID() string {
	return r.Label + ":" + r.Endpoint
}

func (r *CellReference) UnmarshalJSON(data []byte) error {
	var payload map[string]any
	if err := DecodeJSON(data, &payload); err != nil {
		return err
	}
	endpoint, _ := payload["endpoint"].(string)
	if endpoint == "" {
		return fmt.Errorf("CellReference requires endpoint")
	}
	r.Endpoint = endpoint
	if subscribe, ok := payload["subscribeFeed"].(bool); ok {
		r.SubscribeFeed = subscribe
	} else {
		r.SubscribeFeed = true
	}
	r.Label, _ = payload["label"].(string)
	if raw, ok := payload["subscriptions"]; ok {
		data, _ := StableJSON(raw)
		_ = DecodeJSON(data, &r.Subscriptions)
	}
	if r.Subscriptions == nil {
		r.Subscriptions = []CellReference{}
	}
	if raw, ok := payload["setKeysAndValues"]; ok {
		data, _ := StableJSON(raw)
		_ = DecodeJSON(data, &r.SetKeysAndValues)
	}
	if r.SetKeysAndValues == nil {
		r.SetKeysAndValues = []KeyValue{}
	}
	return nil
}

type CellConfiguration struct {
	UUID           string                      `json:"uuid"`
	Name           string                      `json:"name"`
	Description    string                      `json:"description,omitempty"`
	Discovery      *CellConfigurationDiscovery `json:"discovery,omitempty"`
	CellReferences []CellReference             `json:"cellReferences"`
	Skeleton       *SkeletonElement            `json:"skeleton,omitempty"`
}

func NewCellConfiguration(name string) CellConfiguration {
	skeleton, _ := NewSkeletonElement("Text", map[string]any{"text": "Hello HAVEN"})
	return CellConfiguration{
		UUID:           NewUUID(),
		Name:           name,
		CellReferences: []CellReference{},
		Skeleton:       &skeleton,
	}
}

func (c *CellConfiguration) UnmarshalJSON(data []byte) error {
	var payload map[string]any
	if err := DecodeJSON(data, &payload); err != nil {
		return err
	}
	if uuid, ok := payload["uuid"].(string); ok && uuid != "" {
		c.UUID = uuid
	} else {
		c.UUID = NewUUID()
	}
	name, _ := payload["name"].(string)
	if name == "" {
		return fmt.Errorf("CellConfiguration requires name")
	}
	c.Name = name
	c.Description, _ = payload["description"].(string)
	if raw, ok := payload["discovery"]; ok && raw != nil {
		data, _ := StableJSON(raw)
		var discovery CellConfigurationDiscovery
		if err := DecodeJSON(data, &discovery); err != nil {
			return err
		}
		discovery.Normalize()
		c.Discovery = &discovery
	}
	if raw, ok := payload["cellReferences"]; ok && raw != nil {
		data, _ := StableJSON(raw)
		if err := DecodeJSON(data, &c.CellReferences); err != nil {
			return err
		}
	}
	if c.CellReferences == nil {
		c.CellReferences = []CellReference{}
	}
	if raw, ok := payload["skeleton"]; ok && raw != nil {
		data, _ := StableJSON(raw)
		var skeleton SkeletonElement
		if err := DecodeJSON(data, &skeleton); err != nil {
			return err
		}
		c.Skeleton = &skeleton
	}
	return nil
}

func (c CellConfiguration) ReferencesDict() map[string]CellReference {
	out := map[string]CellReference{}
	for _, ref := range c.CellReferences {
		out[ref.ID()] = ref
	}
	return out
}

func (c *CellConfiguration) AddOrReplaceReference(ref CellReference) {
	for i, existing := range c.CellReferences {
		if existing.ID() == ref.ID() {
			c.CellReferences[i] = ref
			return
		}
	}
	c.CellReferences = append(c.CellReferences, ref)
}

func (c *CellConfiguration) RemoveReference(id string) bool {
	for i, ref := range c.CellReferences {
		if ref.ID() == id {
			c.CellReferences = append(c.CellReferences[:i], c.CellReferences[i+1:]...)
			return true
		}
	}
	return false
}

func (c CellConfiguration) SkeletonKeypaths() []string {
	if c.Skeleton == nil {
		return nil
	}
	return c.Skeleton.Keypaths()
}
