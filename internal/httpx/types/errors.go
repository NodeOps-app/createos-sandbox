// Package types holds every request/response struct the createos HTTP
// layer touches. Handlers pass instances of these to httpx.Success /
// httpx.Fail / httpx.Error — the envelope is added there, these are
// the inner `data` payload.
//
// This file contains the small field-level error shapes used in JSend
// "fail" responses (4xx validation / not-found). Server-side errors go
// through httpx.Error with a string message instead.
//
// No helper constructors here — callers write the literal at the
// callsite. `types.FieldError{"name": "is required"}` is shorter
// and more honest than wrapping every common message in a function.
package types

// FieldError is the generic JSend "fail" data shape: one or more field
// names with human-readable messages. Most validation errors fit this.
//
// On the wire: {"<field>": "<message>", ...}
type FieldError map[string]string

// UnknownShape is returned with the catalog so clients can self-correct.
// On the wire: {"shape": "unknown" | "required", "choices": [...]}
type UnknownShape struct {
	Shape   string   `json:"shape"`
	Choices []string `json:"choices"`
}

// AuthError is the standard auth-failure fail body.
// On the wire: {"auth": "<reason>"}
type AuthError struct {
	Auth string `json:"auth"`
}
