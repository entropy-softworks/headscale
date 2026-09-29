package scim

import (
	"slices"
	"strings"
)

// ApplyUserPatch applies normalised operations to u in order and then
// validates the result with [User.Validate], so a PATCH that removes
// userName fails with invalidValue. Membership operations are rejected
// (they cannot come out of [NormalizeUserPatch]). u is modified even when an
// error is returned; apply to a copy if the original must survive.
func ApplyUserPatch(u *User, ops []Operation) error {
	for _, op := range ops {
		var err error

		switch o := op.(type) {
		case SetAttribute:
			err = setUserAttr(u, o)
		case RemoveAttribute:
			err = removeUserAttr(u, o.Path)
		case AddMembers, RemoveMembers, ReplaceMembers:
			err = InvalidPath("users have no members")
		case IgnoredAttribute:
		}

		if err != nil {
			return err
		}
	}

	return u.Validate()
}

func setUserAttr(u *User, o SetAttribute) error {
	p := o.Path

	switch p.String() {
	case attrUserName:
		return setString(&u.UserName, o.Value)
	case attrDisplayName:
		return setString(&u.DisplayName, o.Value)
	case attrExternalID:
		return setString(&u.ExternalID, o.Value)
	case attrActive:
		b, ok := o.Value.(bool)
		if !ok {
			return InvalidValue("active must be a boolean")
		}

		u.Active = new(b)

		return nil
	case "name.formatted", "name.givenName", "name.familyName":
		if u.Name == nil {
			u.Name = &Name{}
		}

		return setString(nameField(u.Name, p.Sub), o.Value)
	}

	if p.Attr != attrEmails {
		return InvalidPath("unsupported attribute %q", p)
	}

	if p.Filter == nil {
		emails, ok := o.Value.([]Email)
		if !ok {
			return InvalidValue("emails must be a list of emails")
		}

		if o.Append {
			u.Emails = appendEmails(u.Emails, emails)
		} else {
			u.Emails = slices.Clone(emails)
		}

		normalisePrimary(u.Emails, -1)

		return nil
	}

	return setEmailSub(u, p, o.Value)
}

func setString(dst *string, v any) error {
	s, ok := v.(string)
	if !ok {
		return InvalidValue("expected a string value")
	}

	*dst = s

	return nil
}

func nameField(n *Name, sub string) *string {
	switch sub {
	case "formatted":
		return &n.Formatted
	case "givenName":
		return &n.GivenName
	default:
		return &n.FamilyName
	}
}

// appendEmails adds emails not already present (by case-insensitive value);
// an existing entry is updated in place instead.
func appendEmails(cur, add []Email) []Email {
	out := slices.Clone(cur)

	for _, e := range add {
		i := slices.IndexFunc(out, func(x Email) bool {
			return strings.EqualFold(x.Value, e.Value)
		})
		if i >= 0 {
			out[i] = e
		} else {
			out = append(out, e)
		}
	}

	return out
}

func emailMatches(filter Expr, e Email) bool {
	m := map[string]any{attrValue: e.Value, attrType: e.Type, attrPrimary: e.Primary}
	if e.Type == "" {
		delete(m, attrType)
	}

	return evalElement(filter, m, attrEmails)
}

func setEmailSub(u *User, p Path, v any) error {
	var idx []int

	for i, e := range u.Emails {
		if emailMatches(p.Filter, e) {
			idx = append(idx, i)
		}
	}

	if len(idx) == 0 {
		// Upsert: seed a new email from the filter's equalities.
		var seed Email

		var eqs []Equality

		collectEqualities(p.Filter, "", &eqs)

		for _, eq := range eqs {
			switch eq.Attr {
			case attrValue:
				seed.Value = eq.Value
			case attrType:
				seed.Type = eq.Value
			}
		}

		u.Emails = append(u.Emails, seed)
		idx = []int{len(u.Emails) - 1}
	}

	if p.Sub == "" {
		patch, ok := v.(EmailPatch)
		if !ok {
			return InvalidValue("%s requires an object value", p)
		}

		for _, i := range idx {
			applyEmailPatch(u.Emails, i, patch)
		}

		return nil
	}

	for _, i := range idx {
		e := &u.Emails[i]

		switch p.Sub {
		case attrValue:
			err := setString(&e.Value, v)
			if err != nil {
				return err
			}
		case attrType:
			err := setString(&e.Type, v)
			if err != nil {
				return err
			}
		case attrPrimary:
			b, ok := v.(bool)
			if !ok {
				return InvalidValue("primary must be a boolean")
			}

			e.Primary = b
			if b {
				normalisePrimary(u.Emails, i)
			}
		default:
			return InvalidPath("unsupported attribute %q", p)
		}
	}

	return nil
}

func applyEmailPatch(emails []Email, i int, patch EmailPatch) {
	e := &emails[i]

	if patch.Value != nil {
		e.Value = *patch.Value
	}

	if patch.Type != nil {
		e.Type = *patch.Type
	}

	if patch.Primary != nil {
		e.Primary = *patch.Primary
		if e.Primary {
			normalisePrimary(emails, i)
		}
	}
}

func removeUserAttr(u *User, p Path) error {
	switch p.String() {
	case attrUserName:
		u.UserName = ""
	case attrDisplayName:
		u.DisplayName = ""
	case attrExternalID:
		u.ExternalID = ""
	case attrActive:
		u.Active = nil
	case attrName:
		u.Name = nil
	case "name.formatted", "name.givenName", "name.familyName":
		if u.Name != nil {
			*nameField(u.Name, p.Sub) = ""
		}
	case attrEmails:
		u.Emails = nil
	default:
		if p.Attr != attrEmails || p.Filter == nil {
			return InvalidPath("unsupported attribute %q", p)
		}

		removeEmails(u, p)
	}

	return nil
}

func removeEmails(u *User, p Path) {
	out := u.Emails[:0]

	for _, e := range u.Emails {
		if !emailMatches(p.Filter, e) {
			out = append(out, e)

			continue
		}

		switch p.Sub {
		case "", attrValue:
			// Removing an email's value removes the email: value is
			// required.
			continue
		case attrType:
			e.Type = ""
		case attrPrimary:
			e.Primary = false
		}

		out = append(out, e)
	}

	if len(out) == 0 {
		out = nil
	}

	u.Emails = out
}

// ApplyGroupPatch applies normalised operations to g in order: displayName
// and externalId are set on g, and membership operations are applied to
// g.Members (new members get only a value; the handler fills display and
// $ref when rendering). It returns the membership operations in order so a
// handler that stores membership as deltas can persist them; a handler that
// stores the full set can use g.MemberIDs() instead. The result is validated
// with [Group.Validate]. Member IDs are not checked for existence; that is
// the handler's job (respond 400 invalidValue or noTarget for unknown ids).
// It runs in time linear in the size of the group and of ops.
func ApplyGroupPatch(g *Group, ops []Operation) ([]Operation, error) {
	var members []Operation

	current := make(map[string]struct{}, len(g.Members))
	for _, m := range g.Members {
		current[m.Value] = struct{}{}
	}

	for _, op := range ops {
		var err error

		switch o := op.(type) {
		case SetAttribute:
			switch o.Path.String() {
			case attrDisplayName:
				err = setString(&g.DisplayName, o.Value)
			case attrExternalID:
				err = setString(&g.ExternalID, o.Value)
			default:
				err = InvalidPath("unsupported attribute %q", o.Path)
			}
		case RemoveAttribute:
			switch o.Path.String() {
			case attrDisplayName:
				g.DisplayName = ""
			case attrExternalID:
				g.ExternalID = ""
			default:
				err = InvalidPath("unsupported attribute %q", o.Path)
			}
		case AddMembers:
			for _, id := range o.IDs {
				if _, ok := current[id]; !ok {
					current[id] = struct{}{}
					g.Members = append(g.Members, Member{Value: id})
				}
			}

			members = append(members, o)
		case RemoveMembers:
			gone := make(map[string]struct{}, len(o.IDs))
			for _, id := range o.IDs {
				gone[id] = struct{}{}

				delete(current, id)
			}

			g.Members = slices.DeleteFunc(g.Members, func(m Member) bool {
				_, ok := gone[m.Value]

				return ok
			})

			members = append(members, o)
		case ReplaceMembers:
			g.Members = nil

			clear(current)

			for _, id := range o.IDs {
				if _, ok := current[id]; !ok {
					current[id] = struct{}{}
					g.Members = append(g.Members, Member{Value: id})
				}
			}

			members = append(members, o)
		case IgnoredAttribute:
		}

		if err != nil {
			return nil, err
		}
	}

	if len(g.Members) == 0 {
		g.Members = nil
	}

	err := g.Validate()
	if err != nil {
		return nil, err
	}

	return members, nil
}
