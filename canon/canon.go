// Package canon implements the canonical encoding shared with the
// Discovery static-snapshot/Ed25519 profile (Discovery-Static-Ed25519.md §3),
// which this audit profile adopts unchanged so that one canonicalizer serves
// both seats:
//
//  1. decode the document as UTF-8 JSON; the top level must be an object;
//  2. remove the signature field(s) structurally, at the top level only;
//  3. re-serialize compactly with object keys sorted by UTF-8 byte order at
//     every depth, escaping exactly `"`, `\` and U+0000–U+001F (two-character
//     forms where defined, lowercase \u00xx otherwise) and nothing else.
//
// Documents with duplicate keys, invalid UTF-8, lone surrogates, or numbers
// other than non-negative integers within 2^53−1 are rejected rather than
// normalized: normalizing them is exactly where two implementations diverge.
package canon

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInteger is the §3 ceiling on every number in a signed document.
const MaxSafeInteger = 1<<53 - 1

// ErrMalformed wraps every rejection so callers can map it to their seat's
// "document invalid" error.
var ErrMalformed = errors.New("malformed document")

// Object is a decoded JSON object. Key order is irrelevant; Encode sorts.
type Object map[string]any

// Number is a validated non-negative integer kept in its decimal form.
type Number string

// Int returns the number's value; the parser has already bounded it.
func (n Number) Int() int64 {
	v, _ := strconv.ParseInt(string(n), 10, 64)
	return v
}

// Parse decodes raw strictly. The result's values are Object, []any, string,
// Number, bool, or nil.
func Parse(raw []byte) (Object, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: invalid UTF-8", ErrMalformed)
	}
	p := &parser{s: raw}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, p.fail("trailing data")
	}
	obj, ok := v.(Object)
	if !ok {
		return nil, fmt.Errorf("%w: top level is not an object", ErrMalformed)
	}
	return obj, nil
}

// SigningBytes returns the canonical bytes of raw with the named top-level
// fields removed — the bytes an Ed25519 signature covers.
func SigningBytes(raw []byte, omit ...string) ([]byte, error) {
	obj, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	for _, k := range omit {
		delete(obj, k)
	}
	return Encode(obj)
}

// Encode serializes v canonically.
func Encode(v any) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encode(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, t)
	case Number:
		b.WriteString(string(t))
	case int:
		return encodeInt(b, int64(t))
	case int64:
		return encodeInt(b, t)
	case uint64:
		if t > MaxSafeInteger {
			return fmt.Errorf("%w: integer out of range", ErrMalformed)
		}
		b.WriteString(strconv.FormatUint(t, 10))
	case Object:
		return encodeObject(b, t)
	case map[string]any:
		return encodeObject(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, e)
		}
		b.WriteByte(']')
	default:
		return fmt.Errorf("%w: unsupported value type %T", ErrMalformed, v)
	}
	return nil
}

func encodeInt(b *strings.Builder, v int64) error {
	if v < 0 || v > MaxSafeInteger {
		return fmt.Errorf("%w: integer out of range", ErrMalformed)
	}
	b.WriteString(strconv.FormatInt(v, 10))
	return nil
}

func encodeObject(b *strings.Builder, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Go compares strings bytewise, which for UTF-8 is §3's byte order.
	sort.Strings(keys)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, k)
		b.WriteByte(':')
		if err := encode(b, m[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

const hexLower = "0123456789abcdef"

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexLower[c>>4])
				b.WriteByte(hexLower[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

// maxDepth bounds recursion on hostile input.
const maxDepth = 64

type parser struct {
	s []byte
	i int
}

func (p *parser) fail(msg string) error {
	return fmt.Errorf("%w: %s at byte %d", ErrMalformed, msg, p.i)
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, p.fail("nesting too deep")
	}
	if p.i >= len(p.s) {
		return nil, p.fail("unexpected end")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		return true, p.lit("true")
	case c == 'f':
		return false, p.lit("false")
	case c == 'n':
		return nil, p.lit("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.fail("unexpected character")
	}
}

func (p *parser) lit(word string) error {
	// bytes.HasPrefix: converting the rest of the input to a string would
	// copy it for every literal, quadratic in the document's size.
	if !bytes.HasPrefix(p.s[p.i:], []byte(word)) {
		return p.fail("invalid literal")
	}
	p.i += len(word)
	return nil
}

func (p *parser) object(depth int) (any, error) {
	p.i++ // {
	obj := Object{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return obj, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.fail("expected object key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := obj[k]; dup {
			return nil, p.fail(fmt.Sprintf("duplicate key %q", k))
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.fail("expected ':'")
		}
		p.i++
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		obj[k] = v
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.fail("unterminated object")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			return obj, nil
		}
		return nil, p.fail("expected ',' or '}'")
	}
}

func (p *parser) array(depth int) (any, error) {
	p.i++ // [
	arr := []any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.fail("unterminated array")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			return arr, nil
		}
		return nil, p.fail("expected ',' or ']'")
	}
}

// number accepts only what §3 permits: non-negative integers, no leading
// zeros, no fraction or exponent, at most 2^53−1.
func (p *parser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		return nil, p.fail("negative numbers are not permitted")
	}
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	if p.i < len(p.s) && (p.s[p.i] == '.' || p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		return nil, p.fail("only integers are permitted")
	}
	digits := string(p.s[start:p.i])
	if len(digits) > 1 && digits[0] == '0' {
		return nil, p.fail("leading zero")
	}
	v, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || v > MaxSafeInteger {
		return nil, p.fail("integer out of range")
	}
	return Number(digits), nil
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.fail("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return "", p.fail("raw control character in string")
		case c == '\\':
			if err := p.escape(&b); err != nil {
				return "", err
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
}

func (p *parser) escape(b *strings.Builder) error {
	p.i++ // backslash
	if p.i >= len(p.s) {
		return p.fail("unterminated escape")
	}
	c := p.s[p.i]
	p.i++
	switch c {
	case '"', '\\', '/':
		b.WriteByte(c)
	case 'b':
		b.WriteByte('\b')
	case 'f':
		b.WriteByte('\f')
	case 'n':
		b.WriteByte('\n')
	case 'r':
		b.WriteByte('\r')
	case 't':
		b.WriteByte('\t')
	case 'u':
		r, err := p.hex4()
		if err != nil {
			return err
		}
		if utf16.IsSurrogate(r) {
			if r >= 0xdc00 {
				return p.fail("lone trailing surrogate")
			}
			if p.i+1 >= len(p.s) || p.s[p.i] != '\\' || p.s[p.i+1] != 'u' {
				return p.fail("lone leading surrogate")
			}
			p.i += 2
			r2, err := p.hex4()
			if err != nil {
				return err
			}
			if r2 < 0xdc00 || r2 > 0xdfff {
				return p.fail("invalid surrogate pair")
			}
			r = utf16.DecodeRune(r, r2)
		}
		b.WriteRune(r)
	default:
		return p.fail("invalid escape")
	}
	return nil
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, p.fail("short \\u escape")
	}
	v, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, p.fail("invalid \\u escape")
	}
	p.i += 4
	return rune(v), nil
}
