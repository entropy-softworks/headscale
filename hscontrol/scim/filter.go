package scim

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxFilterLength bounds the filter expressions ParseFilter accepts. Real
// clients send filters well under 200 bytes.
const MaxFilterLength = 4096

// maxFilterDepth bounds parenthesis/not nesting so a hostile filter cannot
// exhaust the stack.
const maxFilterDepth = 32

// CompareOp is a SCIM filter comparison operator (RFC 7644 section
// 3.4.2.2, table 3). Operators are matched case-insensitively and stored in
// lower case.
type CompareOp string

// Comparison operators.
const (
	OpEq CompareOp = "eq"
	OpNe CompareOp = "ne"
	OpCo CompareOp = "co"
	OpSw CompareOp = "sw"
	OpEw CompareOp = "ew"
	OpGt CompareOp = "gt"
	OpGe CompareOp = "ge"
	OpLt CompareOp = "lt"
	OpLe CompareOp = "le"
)

var compareOps = map[string]CompareOp{
	"eq": OpEq, "ne": OpNe, "co": OpCo, "sw": OpSw, "ew": OpEw,
	"gt": OpGt, "ge": OpGe, "lt": OpLt, "le": OpLe,
}

// LogicalOp is "and" or "or".
type LogicalOp string

// Logical operators.
const (
	OpAnd LogicalOp = "and"
	OpOr  LogicalOp = "or"
)

// AttrPath is an attribute reference in a filter or PATCH path:
// [URI ":"] Attr ["." Sub].
//
// Attr and Sub hold the canonical schema spelling when the attribute is one
// headscale knows (so "USERNAME" becomes "userName"), otherwise the text as
// written. URI is the schema URN prefix as written, or empty. Use
// [AttrPath.IsExtension] to detect attributes of schemas other than core
// User and Group, such as the enterprise extension.
type AttrPath struct {
	URI  string
	Attr string
	Sub  string
}

// String renders the path, e.g. "name.givenName". The URI prefix is kept
// only for extension attributes, where it changes the meaning.
func (p AttrPath) String() string {
	s := p.Attr
	if p.Sub != "" {
		s += "." + p.Sub
	}

	if p.IsExtension() {
		s = p.URI + ":" + s
	}

	return s
}

// IsExtension reports whether the path is qualified with a schema URN other
// than the core User or Group schema (e.g. the enterprise extension).
func (p AttrPath) IsExtension() bool {
	return p.URI != "" && !strings.EqualFold(p.URI, SchemaUser) &&
		!strings.EqualFold(p.URI, SchemaGroup)
}

// Expr is a node of a parsed filter. The concrete types are *CompareExpr,
// *PresentExpr, *LogicalExpr, *NotExpr and *ValuePathExpr.
type Expr interface {
	// String renders the expression in canonical filter syntax; parsing the
	// result yields an equivalent tree.
	String() string
	isExpr()
}

// CompareExpr is "path op value". Value is a string, bool, float64 or nil
// (the null literal).
type CompareExpr struct {
	Path  AttrPath
	Op    CompareOp
	Value any
}

// PresentExpr is "path pr".
type PresentExpr struct {
	Path AttrPath
}

// LogicalExpr is "left and right" or "left or right".
type LogicalExpr struct {
	Op    LogicalOp
	Left  Expr
	Right Expr
}

// NotExpr is "not (x)".
type NotExpr struct {
	X Expr
}

// ValuePathExpr is "attr[filter]": true when some element of the
// multi-valued attribute Path satisfies Filter, whose paths are relative to
// the element (e.g. emails[type eq "work"]).
//
// The Entra ID form `emails[type eq "work"].value eq "x"` is desugared to
// emails[type eq "work" and value eq "x"], which has the same meaning.
type ValuePathExpr struct {
	Path   AttrPath
	Filter Expr
}

func (*CompareExpr) isExpr()   {}
func (*PresentExpr) isExpr()   {}
func (*LogicalExpr) isExpr()   {}
func (*NotExpr) isExpr()       {}
func (*ValuePathExpr) isExpr() {}

func (e *CompareExpr) String() string {
	return e.Path.String() + " " + string(e.Op) + " " + formatLiteral(e.Value)
}

func (e *PresentExpr) String() string {
	return e.Path.String() + " pr"
}

// String parenthesises only where precedence requires it ("or" operands of
// "and"), so long flat conjunctions do not render as deeply nested
// parentheses that would exceed the parser's nesting limit.
func (e *LogicalExpr) String() string {
	return e.operand(e.Left) + " " + string(e.Op) + " " + e.operand(e.Right)
}

func (e *LogicalExpr) operand(x Expr) string {
	if l, ok := x.(*LogicalExpr); ok && e.Op == OpAnd && l.Op == OpOr {
		return "(" + l.String() + ")"
	}

	return x.String()
}

func (e *NotExpr) String() string {
	return "not (" + e.X.String() + ")"
}

func (e *ValuePathExpr) String() string {
	return e.Path.String() + "[" + e.Filter.String() + "]"
}

func formatLiteral(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case string:
		b, err := json.Marshal(x)
		if err != nil {
			return strconv.Quote(x)
		}

		return string(b)
	default:
		return "null"
	}
}

// ParseFilter parses a SCIM filter (RFC 7644 section 3.4.2.2). Supported:
//
//   - attribute paths with optional schema URN prefix and one sub-attribute
//     (userName, name.givenName, urn:...:User:userName); names are
//     case-insensitive;
//   - value paths attr[filter], optionally followed by .subAttr and a
//     comparison (emails[type eq "work"].value eq "x");
//   - operators eq ne co sw ew gt ge lt le pr (case-insensitive);
//   - and, or, not (...), parentheses, with precedence not > and > or;
//   - string (JSON escapes), true/false, null and number literals.
//
// Errors are *Error with scimType invalidFilter.
func ParseFilter(s string) (Expr, error) {
	if len(s) > MaxFilterLength {
		return nil, InvalidFilter("filter longer than %d bytes", MaxFilterLength)
	}

	toks, err := lexFilter(s)
	if err != nil {
		return nil, err
	}

	p := &parser{toks: toks}

	e, err := p.parseOr(false)
	if err != nil {
		return nil, err
	}

	if !p.at(tokEOF) {
		return nil, InvalidFilter("unexpected %s at offset %d", p.peek().desc(), p.peek().pos)
	}

	return e, nil
}

type tokKind int

const (
	tokEOF tokKind = iota
	tokWord
	tokString
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
)

type token struct {
	kind tokKind
	text string // raw word, or decoded string literal
	pos  int
}

func (t token) desc() string {
	switch t.kind {
	case tokEOF:
		return "end of filter"
	case tokString:
		return "string " + strconv.Quote(t.text)
	case tokWord, tokLParen, tokRParen, tokLBracket, tokRBracket:
		return strconv.Quote(t.text)
	}

	return "token"
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func isWordByte(c byte) bool {
	return c > ' ' && c < 0x7f && !strings.ContainsRune(`()[]"`, rune(c))
}

func lexFilter(s string) ([]token, error) {
	var toks []token

	i := 0
	for i < len(s) {
		c := s[i]

		switch {
		case isSpace(c):
			i++
		case c == '(':
			toks = append(toks, token{kind: tokLParen, text: "(", pos: i})
			i++
		case c == ')':
			toks = append(toks, token{kind: tokRParen, text: ")", pos: i})
			i++
		case c == '[':
			toks = append(toks, token{kind: tokLBracket, text: "[", pos: i})
			i++
		case c == ']':
			toks = append(toks, token{kind: tokRBracket, text: "]", pos: i})
			i++
		case c == '"':
			str, n, err := lexString(s[i:])
			if err != nil {
				return nil, InvalidFilter("%v at offset %d", err.Detail, i)
			}

			toks = append(toks, token{kind: tokString, text: str, pos: i})
			i += n
		case isWordByte(c):
			start := i
			for i < len(s) && isWordByte(s[i]) {
				i++
			}

			toks = append(toks, token{kind: tokWord, text: s[start:i], pos: start})
		default:
			return nil, InvalidFilter("unexpected character %q at offset %d", c, i)
		}
	}

	toks = append(toks, token{kind: tokEOF, pos: len(s)})

	return toks, nil
}

// lexString scans a JSON string literal at the start of s and returns its
// decoded value and length in bytes.
func lexString(s string) (string, int, *Error) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			// Reject rather than silently replace invalid UTF-8, which
			// would change the value (and its length) on round trip.
			if !utf8.ValidString(s[:i+1]) {
				return "", 0, InvalidFilter("string literal is not valid UTF-8")
			}

			var out string

			err := json.Unmarshal([]byte(s[:i+1]), &out)
			if err != nil {
				return "", 0, InvalidFilter("invalid string literal")
			}

			return out, i + 1, nil
		}
	}

	return "", 0, InvalidFilter("unterminated string literal")
}

type parser struct {
	toks  []token
	pos   int
	depth int
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}

	return t
}

func (p *parser) at(k tokKind) bool { return p.peek().kind == k }

func (p *parser) atKeyword(kw string) bool {
	t := p.peek()

	return t.kind == tokWord && strings.EqualFold(t.text, kw)
}

func (p *parser) expect(k tokKind, what string) error {
	if !p.at(k) {
		t := p.peek()

		return InvalidFilter("expected %s, got %s at offset %d", what, t.desc(), t.pos)
	}

	p.next()

	return nil
}

// parseOr: or-expr = and-expr *("or" and-expr). inValue marks parsing inside
// a value path, where nested value paths are not allowed.
func (p *parser) parseOr(inValue bool) (Expr, error) {
	left, err := p.parseAnd(inValue)
	if err != nil {
		return nil, err
	}

	for p.atKeyword("or") {
		p.next()

		right, err := p.parseAnd(inValue)
		if err != nil {
			return nil, err
		}

		left = &LogicalExpr{Op: OpOr, Left: left, Right: right}
	}

	return left, nil
}

func (p *parser) parseAnd(inValue bool) (Expr, error) {
	left, err := p.parseUnary(inValue)
	if err != nil {
		return nil, err
	}

	for p.atKeyword("and") {
		p.next()

		right, err := p.parseUnary(inValue)
		if err != nil {
			return nil, err
		}

		left = &LogicalExpr{Op: OpAnd, Left: left, Right: right}
	}

	return left, nil
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxFilterDepth {
		return InvalidFilter("filter nested deeper than %d levels", maxFilterDepth)
	}

	return nil
}

func (p *parser) parseUnary(inValue bool) (Expr, error) {
	err := p.enter()
	if err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()

	// "not" is only an operator when followed by "(", so an attribute
	// literally named "not" still parses.
	if p.atKeyword("not") && p.toks[p.pos+1].kind == tokLParen {
		p.next()
		p.next()

		x, err := p.parseOr(inValue)
		if err != nil {
			return nil, err
		}

		err = p.expect(tokRParen, `")"`)
		if err != nil {
			return nil, err
		}

		return &NotExpr{X: x}, nil
	}

	if p.at(tokLParen) {
		p.next()

		x, err := p.parseOr(inValue)
		if err != nil {
			return nil, err
		}

		err = p.expect(tokRParen, `")"`)
		if err != nil {
			return nil, err
		}

		return x, nil
	}

	return p.parseAttrExpr(inValue)
}

func (p *parser) parseAttrExpr(inValue bool) (Expr, error) {
	t := p.peek()
	if t.kind != tokWord {
		return nil, InvalidFilter("expected attribute path, got %s at offset %d", t.desc(), t.pos)
	}

	p.next()

	path, err := parseAttrPath(t.text)
	if err != nil {
		return nil, err
	}

	// Inside a value path, attributes are sub-attributes of the element;
	// they have no sub-attributes of their own.
	if inValue && (path.Sub != "" || path.URI != "") {
		return nil, InvalidFilter("invalid attribute %q inside value filter at offset %d", t.text, t.pos)
	}

	if !p.at(tokLBracket) {
		return p.parseComparison(path)
	}

	if inValue {
		return nil, InvalidFilter("nested value path at offset %d", p.peek().pos)
	}

	if path.Sub != "" {
		return nil, InvalidFilter("value path on sub-attribute %q", path)
	}

	p.next()

	inner, err := p.parseOr(true)
	if err != nil {
		return nil, err
	}

	closing := p.peek()

	err = p.expect(tokRBracket, `"]"`)
	if err != nil {
		return nil, err
	}

	vp := &ValuePathExpr{Path: path, Filter: inner}

	// emails[type eq "work"].value eq "x": a ".sub" word directly after "]".
	if st, ok := p.subAfter(closing); ok {
		sub := st.text[1:]
		if !validAttrName(sub) {
			return nil, InvalidFilter("invalid sub-attribute %q at offset %d", sub, st.pos)
		}

		rel, err := p.parseComparison(AttrPath{Attr: canonicalSub(path.Attr, sub)})
		if err != nil {
			return nil, err
		}

		vp.Filter = &LogicalExpr{Op: OpAnd, Left: inner, Right: rel}
	}

	return vp, nil
}

// subAfter consumes a ".sub" word that immediately follows the "]" token
// closing (no whitespace in between, as in the RFC grammar). A ".sub" word
// after whitespace is left in place and fails to parse later.
func (p *parser) subAfter(closing token) (token, bool) {
	t := p.peek()
	if t.kind != tokWord || !strings.HasPrefix(t.text, ".") || t.pos != closing.pos+1 {
		return token{}, false
	}

	return p.next(), true
}

func (p *parser) parseComparison(path AttrPath) (Expr, error) {
	t := p.peek()
	if t.kind != tokWord {
		return nil, InvalidFilter("expected operator after %q, got %s at offset %d", path, t.desc(), t.pos)
	}

	p.next()

	opText := strings.ToLower(t.text)
	if opText == "pr" {
		return &PresentExpr{Path: path}, nil
	}

	op, ok := compareOps[opText]
	if !ok {
		return nil, InvalidFilter("unknown operator %q at offset %d", t.text, t.pos)
	}

	vt := p.next()

	var value any

	switch vt.kind {
	case tokString:
		value = vt.text
	case tokWord:
		v, ok := parseLiteral(vt.text)
		if !ok {
			return nil, InvalidFilter("invalid value %q at offset %d", vt.text, vt.pos)
		}

		value = v
	case tokEOF, tokLParen, tokRParen, tokLBracket, tokRBracket:
		return nil, InvalidFilter("expected value after %q, got %s at offset %d", t.text, vt.desc(), vt.pos)
	}

	switch op {
	case OpCo, OpSw, OpEw:
		if _, isStr := value.(string); !isStr {
			return nil, InvalidFilter("operator %q requires a string value", op)
		}
	case OpGt, OpGe, OpLt, OpLe:
		// RFC 7644 section 3.4.2.2: ordering on booleans (and null) is an
		// invalidFilter error.
		switch value.(type) {
		case string, float64:
		default:
			return nil, InvalidFilter("operator %q requires a string, number or date value", op)
		}
	case OpEq, OpNe:
	}

	return &CompareExpr{Path: path, Op: op, Value: value}, nil
}

// parseLiteral parses a non-string literal: true, false, null
// (case-insensitive) or a JSON number. The bool reports success; null yields
// (nil, true).
func parseLiteral(s string) (any, bool) {
	switch strings.ToLower(s) {
	case "true":
		return true, true
	case "false":
		return false, true
	case "null":
		return nil, true
	}

	if s == "" || (s[0] != '-' && (s[0] < '0' || s[0] > '9')) {
		return nil, false
	}

	// Reuse the JSON number grammar: it rejects hex, "inf", "1_000" etc.
	var n float64

	err := json.Unmarshal([]byte(s), &n)
	if err != nil {
		return nil, false
	}

	return n, true
}

// ParseAttrPath parses an attribute path without value filter:
// [URI ":"] attr ["." sub]. See [AttrPath].
func ParseAttrPath(s string) (AttrPath, error) {
	return parseAttrPath(strings.TrimSpace(s))
}

func parseAttrPath(s string) (AttrPath, error) {
	var path AttrPath

	rest := s
	if len(s) > 4 && strings.EqualFold(s[:4], "urn:") {
		i := strings.LastIndexByte(s, ':')
		path.URI = s[:i]
		rest = s[i+1:]
	}

	attr, sub, hasSub := strings.Cut(rest, ".")
	if !validAttrName(attr) || (hasSub && !validAttrName(sub)) {
		return AttrPath{}, InvalidFilter("invalid attribute path %q", s)
	}

	path.Attr = canonicalAttr(attr)
	if hasSub {
		path.Sub = canonicalSub(path.Attr, sub)
	}

	return path, nil
}

// validAttrName implements ATTRNAME = ALPHA *(nameChar) with
// nameChar = "-" / "_" / DIGIT / ALPHA (RFC 7643 section 2.1), plus "$ref".
func validAttrName(s string) bool {
	if s == "$ref" {
		return true
	}

	if s == "" {
		return false
	}

	for i := range len(s) {
		c := s[i]

		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !isAlpha {
			return false
		}

		if !isAlpha && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}

	return true
}
