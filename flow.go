// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

type FlowElementType string

const (
	FlowEvent     FlowElementType = "event"
	FlowAlert     FlowElementType = "alert"
	FlowContent   FlowElementType = "content"
	FlowReference FlowElementType = "reference"
)

type FlowElementContentType string

const (
	ContentString             FlowElementContentType = "string"
	ContentBase64             FlowElementContentType = "base64"
	ContentDSLV17             FlowElementContentType = "dslv17"
	ContentExperienceTemplate FlowElementContentType = "experienceTemplate"
	ContentHTML               FlowElementContentType = "html"
	ContentHTTPRedirect       FlowElementContentType = "httpRedirect"
	ContentRDF                FlowElementContentType = "rdf"
	ContentLogin              FlowElementContentType = "login"
	ContentObject             FlowElementContentType = "object"
)

type FlowProperties struct {
	Mimetype    string                 `json:"mimetype,omitempty"`
	Type        FlowElementType        `json:"type"`
	ContentType FlowElementContentType `json:"contentType,omitempty"`
}

type FlowElement struct {
	ID               string          `json:"id"`
	Sequence         uint64          `json:"sequence,omitempty"`
	Title            string          `json:"title"`
	Topic            string          `json:"topic,omitempty"`
	Content          any             `json:"content"`
	Properties       *FlowProperties `json:"properties,omitempty"`
	Origin           string          `json:"origin,omitempty"`
	ProducerIdentity string          `json:"producerIdentity,omitempty"`
	LogicalTime      uint64          `json:"logicalTime,omitempty"`
	Metadata         map[string]any  `json:"metadata,omitempty"`
	Signature        string          `json:"signature,omitempty"`
}

func NewFlowElement(title string, content any) FlowElement {
	return FlowElement{
		ID:      NewUUID(),
		Title:   title,
		Topic:   "*",
		Content: NormalizeJSON(content),
		Properties: &FlowProperties{
			Type:        FlowContent,
			ContentType: ContentObject,
		},
	}
}
