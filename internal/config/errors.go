package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// FieldError is a validation problem with one configuration setting,
// identified by its path, e.g. "authorization.rules[2].permission".
type FieldError struct {
	Path string
	Msg  string
}

func (e *FieldError) Error() string { return e.Path + ": " + e.Msg }

func fieldErrorf(path, format string, args ...any) error {
	return &FieldError{Path: path, Msg: fmt.Sprintf(format, args...)}
}

var (
	yamlLinePrefix   = regexp.MustCompile(`^(?:yaml: )?line (\d+): `)
	yamlUnknownField = regexp.MustCompile(`^field (\S+) not found in type (\S+)$`)
)

// yamlErrors turns a yaml.v3 decoding error into one "file:line: msg"
// error per problem it reports.
func yamlErrors(file string, err error) error {
	var msgs []string
	if typeErr, ok := errors.AsType[*yaml.TypeError](err); ok {
		msgs = typeErr.Errors
	} else {
		msgs = []string{err.Error()}
	}
	errs := make([]error, 0, len(msgs))
	for _, msg := range msgs {
		pos := file
		if m := yamlLinePrefix.FindStringSubmatch(msg); m != nil {
			pos += ":" + m[1]
			msg = msg[len(m[0]):]
		} else {
			msg = strings.TrimPrefix(msg, "yaml: ")
		}
		if m := yamlUnknownField.FindStringSubmatch(msg); m != nil {
			msg = fmt.Sprintf("unknown field %q", m[1])
			if known := knownFields(m[2]); known != "" {
				msg += " (expected one of: " + known + ")"
			}
		}
		errs = append(errs, fmt.Errorf("%s: %s", pos, msg))
	}
	return errors.Join(errs...)
}

// knownFields lists the YAML keys of the config struct type yaml.v3 names
// typeName (e.g. "config.RuleConfig"), for suggesting what was meant.
func knownFields(typeName string) string {
	var found reflect.Type
	var walk func(t reflect.Type)
	seen := map[reflect.Type]bool{}
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		if t.String() == typeName {
			found = t
		}
		for f := range t.Fields() {
			walk(f.Type)
		}
	}
	walk(reflect.TypeFor[Config]())
	if found == nil {
		return ""
	}
	var names []string
	for f := range found.Fields() {
		if name, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); name != "" && name != "-" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// withLines prefixes each FieldError in err with "file:line", looking its
// path up in the parsed document root. A setting that's missing from the
// file is reported at the closest enclosing setting that's present.
func withLines(file string, root *yaml.Node, err error) error {
	var errs []error
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errs = joined.Unwrap()
	} else {
		errs = []error{err}
	}
	out := make([]error, len(errs))
	for i, e := range errs {
		if fe, ok := errors.AsType[*FieldError](e); ok {
			if line := lineOf(root, fe.Path); line > 0 {
				out[i] = fmt.Errorf("%s:%d: %w", file, line, e)
				continue
			}
		}
		out[i] = fmt.Errorf("%s: %w", file, e)
	}
	return errors.Join(out...)
}

// lineOf returns the line of the setting at path ("a.b[2].c"), or of its
// closest present ancestor, or 0 if nothing matches.
func lineOf(root *yaml.Node, path string) int {
	if root == nil {
		return 0
	}
	n := root
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	line := 0
	for seg := range strings.SplitSeq(path, ".") {
		key, rest, _ := strings.Cut(seg, "[")
		if n.Kind != yaml.MappingNode {
			return line
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				line = n.Content[i].Line
				next = n.Content[i+1]
				break
			}
		}
		if next == nil {
			return line
		}
		n = next
		for rest != "" {
			idxStr, after, _ := strings.Cut(rest, "]")
			rest = strings.TrimPrefix(after, "[")
			idx, err := strconv.Atoi(idxStr)
			if err != nil || n.Kind != yaml.SequenceNode || idx >= len(n.Content) {
				return line
			}
			n = n.Content[idx]
			line = n.Line
		}
	}
	return line
}
