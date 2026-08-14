package loader

import (
	"testing"

	"github.com/chromedp/cdproto/runtime"
)

func str(v string) *runtime.RemoteObject {
	return &runtime.RemoteObject{Type: runtime.TypeString, Value: []byte(`"` + v + `"`)}
}

func TestRenderArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		obj  *runtime.RemoteObject
		want string
	}{
		{
			name: "nil object is not reported as undefined",
			obj:  nil,
			want: nilObject,
		},
		{
			name: "string is unquoted and unescaped from its raw JSON",
			obj:  &runtime.RemoteObject{Type: runtime.TypeString, Value: []byte(`"he said \"hi\""`)},
			want: `he said "hi"`,
		},
		{
			name: "number",
			obj:  &runtime.RemoteObject{Type: runtime.TypeNumber, Value: []byte(`42.5`)},
			want: "42.5",
		},
		{
			name: "bool",
			obj:  &runtime.RemoteObject{Type: runtime.TypeBoolean, Value: []byte(`true`)},
			want: "true",
		},
		{
			name: "undefined",
			obj:  &runtime.RemoteObject{Type: runtime.TypeUndefined},
			want: "undefined",
		},
		{
			name: "null arrives as an object with the null subtype",
			obj:  &runtime.RemoteObject{Type: runtime.TypeObject, Subtype: runtime.SubtypeNull, Value: []byte(`null`)},
			want: "null",
		},
		{
			name: "NaN has no JSON encoding and arrives unserializable",
			obj:  &runtime.RemoteObject{Type: runtime.TypeNumber, UnserializableValue: "NaN"},
			want: "NaN",
		},
		{
			name: "Infinity",
			obj:  &runtime.RemoteObject{Type: runtime.TypeNumber, UnserializableValue: "-Infinity"},
			want: "-Infinity",
		},
		{
			name: "BigInt",
			obj:  &runtime.RemoteObject{Type: runtime.TypeBigint, UnserializableValue: "9007199254740993n"},
			want: "9007199254740993n",
		},
		{
			name: "error subtype keeps the stack-bearing description",
			obj: &runtime.RemoteObject{
				Type:        runtime.TypeObject,
				Subtype:     runtime.SubtypeError,
				ClassName:   "TypeError",
				Description: "TypeError: x is not a function\n    at boom (https://ex.test/a.js:3:9)",
			},
			want: "TypeError: x is not a function\n    at boom (https://ex.test/a.js:3:9)",
		},
		{
			name: "error subtype without a description falls back to the class name",
			obj: &runtime.RemoteObject{
				Type:      runtime.TypeObject,
				Subtype:   runtime.SubtypeError,
				ClassName: "RangeError",
			},
			want: "RangeError",
		},
		{
			name: "function",
			obj: &runtime.RemoteObject{
				Type:        runtime.TypeFunction,
				ClassName:   "Function",
				Description: "function retry() { }",
			},
			want: "function retry() { }",
		},
		{
			name: "symbol",
			obj:  &runtime.RemoteObject{Type: runtime.TypeSymbol, Description: "Symbol(id)"},
			want: "Symbol(id)",
		},
		{
			name: "object preview",
			obj: &runtime.RemoteObject{
				Type:      runtime.TypeObject,
				ClassName: "Object",
				Preview: &runtime.ObjectPreview{
					Type:        runtime.TypeObject,
					Description: "Object",
					Properties: []*runtime.PropertyPreview{
						{Name: "status", Type: runtime.TypeNumber, Value: "500"},
						{Name: "url", Type: runtime.TypeString, Value: "/api"},
					},
				},
			},
			want: "{status: 500, url: /api}",
		},
		{
			name: "object preview with overflow appends the DevTools marker",
			obj: &runtime.RemoteObject{
				Type:      runtime.TypeObject,
				ClassName: "Config",
				Preview: &runtime.ObjectPreview{
					Type:        runtime.TypeObject,
					Description: "Config",
					Overflow:    true,
					Properties: []*runtime.PropertyPreview{
						{Name: "a", Type: runtime.TypeNumber, Value: "1"},
					},
				},
			},
			want: "Config {a: 1" + previewOverflow + "}",
		},
		{
			name: "empty overflowing preview still says it was clipped",
			obj: &runtime.RemoteObject{
				Type: runtime.TypeObject,
				Preview: &runtime.ObjectPreview{
					Type:        runtime.TypeObject,
					Description: "Object",
					Overflow:    true,
				},
			},
			want: "{…}",
		},
		{
			name: "array preview",
			obj: &runtime.RemoteObject{
				Type:    runtime.TypeObject,
				Subtype: runtime.SubtypeArray,
				Preview: &runtime.ObjectPreview{
					Type:    runtime.TypeObject,
					Subtype: runtime.SubtypeArray,
					Properties: []*runtime.PropertyPreview{
						{Name: "0", Type: runtime.TypeNumber, Value: "1"},
						{Name: "1", Type: runtime.TypeNumber, Value: "2"},
					},
				},
			},
			want: "[1, 2]",
		},
		{
			name: "nested preview is expanded",
			obj: &runtime.RemoteObject{
				Type: runtime.TypeObject,
				Preview: &runtime.ObjectPreview{
					Type:        runtime.TypeObject,
					Description: "Object",
					Properties: []*runtime.PropertyPreview{
						{
							Name: "inner",
							Type: runtime.TypeObject,
							ValuePreview: &runtime.ObjectPreview{
								Type:        runtime.TypeObject,
								Description: "Object",
								Properties: []*runtime.PropertyPreview{
									{Name: "k", Type: runtime.TypeNumber, Value: "7"},
								},
							},
						},
					},
				},
			},
			want: "{inner: {k: 7}}",
		},
		{
			name: "opaque object with nothing to render",
			obj:  &runtime.RemoteObject{Type: runtime.TypeObject},
			want: opaqueValue,
		},
		{
			name: "object with no preview falls back to its raw JSON value",
			obj:  &runtime.RemoteObject{Type: runtime.TypeObject, Value: []byte(`{"a":1}`)},
			want: `{"a":1}`,
		},
		{
			name: "object with neither preview nor value falls back to the class name",
			obj:  &runtime.RemoteObject{Type: runtime.TypeObject, ClassName: "Request"},
			want: "Request",
		},
		{
			name: "an uninvoked getter shows the DevTools placeholder",
			obj:  &runtime.RemoteObject{Type: runtime.TypeAccessor},
			want: "(...)",
		},
		{
			name: "symbol without a description",
			obj:  &runtime.RemoteObject{Type: runtime.TypeSymbol},
			want: "Symbol()",
		},
		{
			name: "function without a description",
			obj:  &runtime.RemoteObject{Type: runtime.TypeFunction},
			want: "function",
		},
		{
			name: "a string whose Value is not a JSON literal falls back to Description",
			obj:  &runtime.RemoteObject{Type: runtime.TypeString, Value: []byte(`oops`), Description: "oops"},
			want: "oops",
		},
		{
			name: "a string carrying nothing at all renders empty rather than inventing a value",
			obj:  &runtime.RemoteObject{Type: runtime.TypeString},
			want: "",
		},
		{
			name: "an unknown object type falls back to whatever is populated",
			obj:  &runtime.RemoteObject{Type: "quantum", Description: "weird"},
			want: "weird",
		},
		{
			name: "an unknown object type with nothing populated names the type",
			obj:  &runtime.RemoteObject{Type: "quantum"},
			want: "quantum",
		},
		{
			name: "preview properties without a value fall back to subtype then type, nils skipped",
			obj: &runtime.RemoteObject{
				Type: runtime.TypeObject,
				Preview: &runtime.ObjectPreview{
					Type:        runtime.TypeObject,
					Description: "Object",
					Properties: []*runtime.PropertyPreview{
						{Name: "node", Type: runtime.TypeObject, Subtype: runtime.SubtypeNode},
						{Name: "fn", Type: runtime.TypeFunction},
						nil,
					},
				},
			},
			want: "{node: node, fn: function}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := renderArg(tt.obj); got != tt.want {
				t.Errorf("renderArg() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []*runtime.RemoteObject
		want string
	}{
		{name: "no args", args: nil, want: ""},
		{name: "single arg is not padded", args: []*runtime.RemoteObject{str("boom")}, want: "boom"},
		{
			name: "multiple args join with a single space, DevTools style",
			args: []*runtime.RemoteObject{
				str("load failed:"),
				{Type: runtime.TypeNumber, Value: []byte(`503`)},
				{Type: runtime.TypeObject, Subtype: runtime.SubtypeError, Description: "Error: nope"},
			},
			want: "load failed: 503 Error: nope",
		},
		{
			name: "a nil arg does not lose the rest of the message",
			args: []*runtime.RemoteObject{str("a"), nil, str("b")},
			want: "a " + nilObject + " b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := renderArgs(tt.args); got != tt.want {
				t.Errorf("renderArgs() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFirstFrame(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		stack *runtime.StackTrace
		want  string
	}{
		{name: "nil stack trace", stack: nil, want: ""},
		{name: "no call frames", stack: &runtime.StackTrace{}, want: ""},
		{
			name: "positions are rendered 1-based although CDP is 0-based",
			stack: &runtime.StackTrace{CallFrames: []*runtime.CallFrame{
				{FunctionName: "boom", URL: "https://ex.test/a.js", LineNumber: 0, ColumnNumber: 0},
			}},
			want: "boom (https://ex.test/a.js:1:1)",
		},
		{
			name: "an unnamed function is labeled rather than left blank",
			stack: &runtime.StackTrace{CallFrames: []*runtime.CallFrame{
				{URL: "https://ex.test/a.js", LineNumber: 11, ColumnNumber: 4},
			}},
			want: anonFrame + " (https://ex.test/a.js:12:5)",
		},
		{
			name: "an empty synchronous stack falls through to the async parent",
			stack: &runtime.StackTrace{
				Parent: &runtime.StackTrace{CallFrames: []*runtime.CallFrame{
					{FunctionName: "tick", URL: "https://ex.test/b.js", LineNumber: 2, ColumnNumber: 2},
				}},
			},
			want: "tick (https://ex.test/b.js:3:3)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := firstFrame(tt.stack); got != tt.want {
				t.Errorf("firstFrame() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderException(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		details    *runtime.ExceptionDetails
		wantText   string
		wantFrame  string
		wantSource string
		wantLine   int64
		wantCol    int64
	}{
		{
			name:    "nil details render to nothing",
			details: nil,
		},
		{
			name: "the exception description wins over the bare Text",
			details: &runtime.ExceptionDetails{
				Text:         "Uncaught",
				URL:          "https://ex.test/a.js",
				LineNumber:   4,
				ColumnNumber: 8,
				Exception: &runtime.RemoteObject{
					Type: runtime.TypeObject, Subtype: runtime.SubtypeError,
					Description: "TypeError: nope",
				},
			},
			wantText:   "TypeError: nope",
			wantSource: "https://ex.test/a.js",
			wantLine:   4,
			wantCol:    8,
		},
		{
			name: "a thrown primitive is appended to Text, which alone says nothing",
			details: &runtime.ExceptionDetails{
				Text:      "Uncaught",
				URL:       "https://ex.test/a.js",
				Exception: str("boom"),
			},
			wantText:   "Uncaught boom",
			wantSource: "https://ex.test/a.js",
		},
		{
			name: "an exception object that renders to nothing leaves Text alone",
			details: &runtime.ExceptionDetails{
				Text:      "Uncaught",
				URL:       "https://ex.test/a.js",
				Exception: &runtime.RemoteObject{Type: runtime.TypeString},
			},
			wantText:   "Uncaught",
			wantSource: "https://ex.test/a.js",
		},
		{
			name: "no exception object at all falls back to Text",
			details: &runtime.ExceptionDetails{
				Text: "Uncaught SyntaxError: Unexpected token '<'",
				URL:  "https://ex.test/a.js",
			},
			wantText:   "Uncaught SyntaxError: Unexpected token '<'",
			wantSource: "https://ex.test/a.js",
		},
		{
			name: "a missing URL is recovered from the stack, positions included",
			details: &runtime.ExceptionDetails{
				Text: "Uncaught",
				StackTrace: &runtime.StackTrace{CallFrames: []*runtime.CallFrame{
					{FunctionName: "run", URL: "https://ex.test/inline", LineNumber: 6, ColumnNumber: 1},
				}},
				Exception: &runtime.RemoteObject{
					Type: runtime.TypeObject, Subtype: runtime.SubtypeError,
					Description: "Error: inline",
				},
			},
			wantText:   "Error: inline",
			wantFrame:  "run (https://ex.test/inline:7:2)",
			wantSource: "https://ex.test/inline",
			wantLine:   6,
			wantCol:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			text, frame, source, line, col := renderException(tt.details)
			if text != tt.wantText {
				t.Errorf("text = %q, want %q", text, tt.wantText)
			}
			if frame != tt.wantFrame {
				t.Errorf("frame = %q, want %q", frame, tt.wantFrame)
			}
			if source != tt.wantSource {
				t.Errorf("source = %q, want %q", source, tt.wantSource)
			}
			if line != tt.wantLine || col != tt.wantCol {
				t.Errorf("position = %d:%d, want %d:%d", line, col, tt.wantLine, tt.wantCol)
			}
		})
	}
}

func TestUnquoteJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		in    string
		want  string
		wantK bool
	}{
		{name: "plain string", in: `"hi"`, want: "hi", wantK: true},
		{name: "escapes are decoded", in: `"a\nb c"`, want: "a\nb c", wantK: true},
		{name: "empty string", in: `""`, want: "", wantK: true},
		{name: "not a string literal", in: `42`, wantK: false},
		{name: "empty input", in: ``, wantK: false},
		{name: "malformed literal", in: `"unterminated`, wantK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := unquoteJSON([]byte(tt.in))
			if ok != tt.wantK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantK)
			}
			if ok && got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
