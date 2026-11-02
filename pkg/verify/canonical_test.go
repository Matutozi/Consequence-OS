package verify

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// The example from RFC 8785 section 3.2.2.
		{
			name: "rfc 8785 example",
			in: `{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
			      "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
			      "literals": [null, true, false]}`,
			want: `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		// The key sorting example from RFC 8785 section 3.2.3.
		{
			name: "rfc 8785 sorting",
			in:   `{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}`,
			want: `{"\r":"Carriage Return","1":"One","` + "\u0080" + `":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}`,
		},
		{"whitespace removed", " { \"b\" : 1 ,\n \"a\" : [ 1 , 2 ] } ", `{"a":[1,2],"b":1}`},
		{"nested objects sorted", `{"z":{"y":1,"x":2},"a":0}`, `{"a":0,"z":{"x":2,"y":1}}`},
		{"empty object", `{}`, `{}`},
		{"empty array", `[]`, `[]`},
		{"scalar", `"hi"`, `"hi"`},
		{"html is not escaped", `{"a":"<b>&</b>"}`, `{"a":"<b>&</b>"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestFormatNumber(t *testing.T) {
	// Expected values follow JavaScript's Number.prototype.toString.
	tests := []struct{ in, want string }{
		{"0", "0"},
		{"-0", "0"},
		{"1", "1"},
		{"-1", "-1"},
		{"4.50", "4.5"},
		{"5000", "5000"},
		{"4800.00", "4800"},
		{"0.1", "0.1"},
		{"2e-3", "0.002"},
		{"0.000001", "0.000001"},
		{"1e-7", "1e-7"},
		{"1.5e-7", "1.5e-7"},
		{"1e20", "100000000000000000000"},
		{"1e21", "1e+21"},
		{"123456789012345680000", "123456789012345680000"},
		{"9007199254740992", "9007199254740992"},
		{"333333333.33333329", "333333333.3333333"},
		{"5e-324", "5e-324"},
		{"1.7976931348623157e308", "1.7976931348623157e+308"},
		{"-1.25e+25", "-1.25e+25"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"duplicate key", `{"amount":10,"amount":5000}`, "duplicate object key"},
		{"nested duplicate key", `{"a":{"x":1,"x":2}}`, "duplicate object key"},
		{"number out of range", `{"a":1e400}`, "out of range"},
		{"trailing data", `{"a":1} {"b":2}`, "after the JSON value"},
		{"broken JSON", `{"a":}`, "invalid JSON"},
		{"empty input", ``, "invalid JSON"},
		{"invalid utf-8", "{\"a\":\"\xff\"}", "UTF-8"},
		{"too deep", strings.Repeat("[", 200) + strings.Repeat("]", 200), "nested deeper"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Canonicalize([]byte(tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
	if _, err := Canonicalize([]byte(`{"a":1,"a":2}`)); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("errors.Is(err, ErrDuplicateKey) = false for %v", err)
	}
}

func TestParamsHash(t *testing.T) {
	// sha256 of the two bytes "{}".
	const emptyHash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

	tests := []struct {
		name string
		a, b string
		same bool
	}{
		{"key order does not matter", `{"amount":4800,"po":"00231"}`, `{"po":"00231","amount":4800}`, true},
		{"spacing does not matter", `{"amount":4800}`, `{ "amount" : 4800 }`, true},
		{"number spelling does not matter", `{"amount":4800}`, `{"amount":4.8e3}`, true},
		{"value change matters", `{"amount":4800}`, `{"amount":48000}`, false},
		{"type change matters", `{"amount":4800}`, `{"amount":"4800"}`, false},
		{"null is empty", `null`, `{}`, true},
		{"absent is empty", ``, `{}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha, err := ParamsHash([]byte(tt.a))
			if err != nil {
				t.Fatal(err)
			}
			hb, err := ParamsHash([]byte(tt.b))
			if err != nil {
				t.Fatal(err)
			}
			if (ha == hb) != tt.same {
				t.Errorf("hash(%s)=%s hash(%s)=%s, same=%v want %v", tt.a, ha, tt.b, hb, ha == hb, tt.same)
			}
		})
	}

	got, _ := ParamsHash(nil)
	if got != emptyHash {
		t.Errorf("ParamsHash(nil) = %s, want %s", got, emptyHash)
	}
}
