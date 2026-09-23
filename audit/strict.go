package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"onym-audit/canon"
)

// shape pins the exact key set of one JSON object level. Go's
// encoding/json matches keys case-insensitively, so strictness is enforced
// here, on the canonical parse, before any typed decode.
type shape struct {
	required []string
	optional []string
	nested   map[string]*shape // object-valued (or array-of-object-valued) keys
}

func (s *shape) check(path string, obj canon.Object) error {
	allowed := map[string]bool{}
	for _, k := range s.required {
		allowed[k] = true
		if _, ok := obj[k]; !ok {
			return fmt.Errorf("%s: missing required field %q", path, k)
		}
	}
	for _, k := range s.optional {
		allowed[k] = true
	}
	var unknown []string
	for k := range obj {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("%s: unknown field(s) %s", path, strings.Join(unknown, ", "))
	}
	for k, sub := range s.nested {
		switch v := obj[k].(type) {
		case canon.Object:
			if err := sub.check(path+"."+k, v); err != nil {
				return err
			}
		case []any:
			for i, e := range v {
				o, ok := e.(canon.Object)
				if !ok {
					return fmt.Errorf("%s.%s[%d]: expected object", path, k, i)
				}
				if err := sub.check(fmt.Sprintf("%s.%s[%d]", path, k, i), o); err != nil {
					return err
				}
			}
		case nil:
			// absent optional or explicit null: typed validation decides
		default:
			return fmt.Errorf("%s.%s: expected object", path, k)
		}
	}
	return nil
}

// decodeStrict parses raw canonically, checks its key set against s, and
// decodes it into out.
func decodeStrict(raw []byte, s *shape, out any) error {
	obj, err := canon.Parse(raw)
	if err != nil {
		return err
	}
	if err := s.check("$", obj); err != nil {
		return fmt.Errorf("%w: %v", canon.ErrMalformed, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: %v", canon.ErrMalformed, err)
	}
	return nil
}

// toObject converts a typed document to its canonical object form.
func toObject(v any) (canon.Object, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canon.Parse(b)
}

var (
	componentRE = regexp.MustCompile(`^onym:component:[a-z0-9-]{1,64}$`)
	idRE        = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	offerIDRE   = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	commitRE    = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
)
