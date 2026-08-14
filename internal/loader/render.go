package loader

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/chromedp/cdproto/runtime"
)

// The renderers in this file are pure functions of the event payload, and that
// is the whole point of them.
//
// The accurate way to stringify a Runtime.RemoteObject is
// Runtime.callFunctionOn with a toString-ish function — but that is a CDP
// round-trip, and every console message originates on chromedp's event
// goroutine, which is also the goroutine that would have to deliver the
// round-trip's reply. Issuing one from the event path deadlocks the browser
// connection. So we render from what consoleAPICalled and exceptionThrown
// already carry: Value (raw JSON), UnserializableValue (NaN, Infinity, 1n),
// Description (populated for errors and functions), ClassName and Preview.
//
// The occasional "[object]" is the price, and it is much cheaper than a hang.

const (
	// previewOverflow is DevTools' own marker for "Chrome clipped this object",
	// kept so a reader can tell it apart from our own message cap.
	previewOverflow = ", …"

	// maxPreviewDepth bounds nested preview expansion. Chrome nests at most two
	// levels, but the structure is attacker-controlled and recursion here runs
	// while snapshot() holds the collector lock.
	maxPreviewDepth = 2

	nilObject   = "<nil>"
	anonFrame   = "(anonymous)"
	opaqueValue = "[object]"
)

// renderArg turns one RemoteObject into the string a developer would see in the
// DevTools console.
func renderArg(o *runtime.RemoteObject) string {
	if o == nil {
		// A protocol anomaly, not a JavaScript value — saying "undefined" here
		// would misreport what the page logged.
		return nilObject
	}

	// NaN, Infinity, -0 and BigInt literals have no JSON encoding, so V8 sends
	// them here and leaves Value empty.
	if o.UnserializableValue != "" {
		return string(o.UnserializableValue)
	}

	switch o.Type {
	case runtime.TypeString:
		// Value is raw JSON, so a logged string arrives quoted and escaped.
		if s, ok := unquoteJSON(o.Value); ok {
			return s
		}
		return firstNonEmpty(o.Description, string(o.Value))
	case runtime.TypeNumber, runtime.TypeBoolean, runtime.TypeBigint:
		return firstNonEmpty(string(o.Value), o.Description)
	case runtime.TypeUndefined:
		return "undefined"
	case runtime.TypeSymbol:
		return firstNonEmpty(o.Description, "Symbol()")
	case runtime.TypeFunction:
		return firstNonEmpty(o.Description, o.ClassName, "function")
	case runtime.TypeAccessor:
		// A getter that was not invoked; DevTools shows the same placeholder.
		return "(...)"
	case runtime.TypeObject:
		return renderObject(o, maxPreviewDepth)
	}
	return firstNonEmpty(o.Description, string(o.Value), string(o.Type))
}

func renderObject(o *runtime.RemoteObject, depth int) string {
	switch o.Subtype {
	case runtime.SubtypeNull:
		return "null"
	case runtime.SubtypeError:
		// For an Error, Description is "TypeError: x is not a function\n    at
		// ..." — the message AND the stack. That is the single most valuable
		// string in the whole protocol for this tool's purpose.
		if o.Description != "" {
			return o.Description
		}
	}
	if o.Preview != nil && depth > 0 {
		return renderPreview(o.Preview, depth)
	}
	if len(o.Value) > 0 {
		return string(o.Value)
	}
	return firstNonEmpty(o.Description, o.ClassName, opaqueValue)
}

func renderPreview(p *runtime.ObjectPreview, depth int) string {
	openTok, closeTok := "{", "}"
	array := p.Subtype == runtime.SubtypeArray
	if array {
		openTok, closeTok = "[", "]"
	}

	var b strings.Builder
	if !array && p.Description != "" && p.Description != "Object" {
		// The constructor name, when it is not the useless default.
		b.WriteString(p.Description)
		b.WriteByte(' ')
	}
	b.WriteString(openTok)
	written := 0
	for _, prop := range p.Properties {
		if prop == nil {
			continue
		}
		if written > 0 {
			b.WriteString(", ")
		}
		if !array {
			b.WriteString(prop.Name)
			b.WriteString(": ")
		}
		b.WriteString(renderProperty(prop, depth-1))
		written++
	}
	if p.Overflow {
		if written == 0 {
			b.WriteString("…")
		} else {
			b.WriteString(previewOverflow)
		}
	}
	b.WriteString(closeTok)
	return b.String()
}

// renderProperty renders one already-non-nil preview property; renderPreview
// filters the nils out so the separator logic stays correct.
func renderProperty(p *runtime.PropertyPreview, depth int) string {
	if p.Value != "" {
		return p.Value
	}
	if p.ValuePreview != nil && depth > 0 {
		return renderPreview(p.ValuePreview, depth)
	}
	if p.Subtype != "" {
		return string(p.Subtype)
	}
	return string(p.Type)
}

// renderArgs joins one console call's arguments the way the DevTools console
// does: in order, space-separated, so console.error("load failed:", err) reads
// as "load failed: TypeError: ...".
func renderArgs(args []*runtime.RemoteObject) string {
	switch len(args) {
	case 0:
		return ""
	case 1:
		return renderArg(args[0])
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, renderArg(a))
	}
	return strings.Join(parts, " ")
}

// renderException flattens Runtime.ExceptionDetails into the pieces of a
// verdict.ConsoleError.
//
// line and col are returned exactly as CDP reported them — 0-based. The caller
// converts, so that the conversion happens in one place next to the field it
// populates.
func renderException(d *runtime.ExceptionDetails) (text, frame, source string, line, col int64) {
	if d == nil {
		return "", "", "", 0, 0
	}

	switch {
	case d.Exception != nil && d.Exception.Description != "":
		// Preferred: this carries the message AND the stack. ExceptionDetails.Text
		// is usually just the word "Uncaught".
		text = d.Exception.Description
	case d.Exception != nil:
		// A thrown non-Error (`throw "boom"`) has no Description, and Text alone
		// would say nothing, so the value has to be appended.
		if v := renderArg(d.Exception); v != "" && v != nilObject {
			text = strings.TrimSpace(d.Text + " " + v)
		} else {
			text = d.Text
		}
	default:
		text = d.Text
	}

	frame = firstFrame(d.StackTrace)
	source, line, col = d.URL, d.LineNumber, d.ColumnNumber
	if fr := firstCallFrame(d.StackTrace); fr != nil {
		// Chrome omits URL for exceptions from eval'd or inline script; the
		// stack still knows where it happened.
		if source == "" {
			source = fr.URL
			if line == 0 && col == 0 {
				line, col = fr.LineNumber, fr.ColumnNumber
			}
		}
	}
	return text, frame, source, line, col
}

// firstFrame renders the innermost stack frame as "fn (url:line:col)", with the
// 1-based positions DevTools displays.
func firstFrame(st *runtime.StackTrace) string {
	fr := firstCallFrame(st)
	if fr == nil {
		return ""
	}
	name := fr.FunctionName
	if name == "" {
		name = anonFrame
	}

	var b strings.Builder
	b.WriteString(name)
	b.WriteString(" (")
	b.WriteString(fr.URL)
	b.WriteByte(':')
	b.WriteString(strconv.FormatInt(fr.LineNumber+1, 10))
	b.WriteByte(':')
	b.WriteString(strconv.FormatInt(fr.ColumnNumber+1, 10))
	b.WriteByte(')')
	return b.String()
}

// firstCallFrame returns the innermost frame, walking into the async parent
// chain when the synchronous frame list is empty — which is what a stack
// captured inside a promise callback looks like.
func firstCallFrame(st *runtime.StackTrace) *runtime.CallFrame {
	for ; st != nil; st = st.Parent {
		for _, fr := range st.CallFrames {
			if fr != nil {
				return fr
			}
		}
	}
	return nil
}

// unquoteJSON decodes a JSON string literal, reporting false for anything that
// is not one.
func unquoteJSON(v []byte) (string, bool) {
	if len(v) < 2 || v[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
