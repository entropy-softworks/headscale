package apiscim

import (
	"cmp"
	"errors"
	"math"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scim"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
)

// emailType is the type of the one email headscale stores per user.
const emailType = "work"

// Attribute names the list handlers look up in the database.
const (
	attrUserName    = "userName"
	attrExternalID  = "externalId"
	attrDisplayName = "displayName"
	attrEmailsValue = "emails.value"
)

// userError maps the persistence errors of a user endpoint to SCIM errors.
// Conflict details are fixed: the cause names other users, and is logged
// instead.
func userError(err error) *scim.Error {
	if errors.Is(err, hsdb.ErrSCIMInvalid) {
		return scim.InvalidValue("%s", strings.TrimPrefix(err.Error(), "scim: "))
	}

	return scim.MapError(err,
		scim.ErrorMapping{Match: hsdb.ErrUserNotFound, Result: scim.NotFound("user not found")},
		scim.ErrorMapping{
			Match:  hsdb.ErrSCIMConflict,
			Result: scim.Uniqueness("the userName, externalId or email is already held by another user"),
		},
	)
}

// toSCIMUser renders a stored SCIM user. It reads the SCIM columns, not the
// core ones a login owns once the user is linked.
func toSCIMUser(base string, u *types.User) *scim.User {
	id := formatID(u.ID)
	out := &scim.User{
		ID:          id,
		ExternalID:  u.ExternalID.String,
		UserName:    u.SCIMUserName.String,
		DisplayName: u.SCIMDisplayName,
		Active:      new(!u.IsSuspended()),
		Meta: &scim.Meta{
			ResourceType: scim.ResourceTypeUser,
			Created:      u.CreatedAt.UTC(),
			LastModified: u.UpdatedAt.UTC(),
			Location:     scim.UserLocation(base, id),
		},
	}

	if u.GivenName != "" || u.FamilyName != "" {
		out.Name = &scim.Name{GivenName: u.GivenName, FamilyName: u.FamilyName}
	}

	if u.SCIMEmail != "" {
		out.Emails = []scim.Email{{Value: u.SCIMEmail, Type: emailType, Primary: true}}
	}

	memberships := slices.Clone(u.Memberships)
	slices.SortFunc(memberships, func(a, b types.UserGroup) int {
		return cmp.Compare(a.GroupID, b.GroupID)
	})

	for _, m := range memberships {
		if m.Source != types.GroupSourceSCIM || !m.Group.IsSCIM() {
			continue
		}

		gid := formatID(m.GroupID)
		out.Groups = append(out.Groups, scim.GroupRef{
			Value:   gid,
			Ref:     scim.GroupLocation(base, gid),
			Display: groupDisplayName(&m.Group),
		})
	}

	return out
}

// userFromAttributes is the SCIM user a PATCH starts from.
func userFromAttributes(a types.SCIMUserAttributes) *scim.User {
	u := &scim.User{
		UserName:    a.UserName,
		ExternalID:  a.ExternalID,
		DisplayName: a.DisplayName,
		Active:      new(a.Active),
	}

	if a.GivenName != "" || a.FamilyName != "" {
		u.Name = &scim.Name{GivenName: a.GivenName, FamilyName: a.FamilyName}
	}

	if a.Email != "" {
		u.Emails = []scim.Email{{Value: a.Email, Type: emailType, Primary: true}}
	}

	return u
}

// attributesFromUser is what headscale stores of a SCIM user: the primary
// email only, and no name.formatted. current is the stored active state,
// kept when u leaves active unset.
func attributesFromUser(u *scim.User, current bool) types.SCIMUserAttributes {
	a := types.SCIMUserAttributes{
		UserName:    u.UserName,
		ExternalID:  u.ExternalID,
		DisplayName: u.DisplayName,
		Email:       u.PrimaryEmail(),
		Active:      current,
	}

	if u.Name != nil {
		a.GivenName = u.Name.GivenName
		a.FamilyName = u.Name.FamilyName
	}

	if u.Active != nil {
		a.Active = *u.Active
	}

	return a
}

// userID resolves the {id} of a user route.
func userID(r *http.Request) (types.UserID, error) {
	id, ok := parseID(chi.URLParam(r, "id"))
	if !ok {
		return 0, scim.NotFound("user not found")
	}

	return types.UserID(id), nil
}

// userFilterAttrs are the attributes a user list can look up in the
// database; exactUserAttrs those whose database comparison is exactly
// scim.Match's, so a filter consisting of one of them needs no in-memory pass.
var (
	userFilterAttrs = []string{attrUserName, attrExternalID, attrEmailsValue}
	exactUserAttrs  = []string{attrUserName, attrExternalID}
)

func (a *api) listUsers(w http.ResponseWriter, r *http.Request) {
	req, err := scim.ParseListRequest(r.URL.Query())
	if err != nil {
		writeError(w, r, err)

		return
	}

	var filter hsdb.SCIMUserFilter

	eq, narrowed := scim.ExtractEquality(req.Filter, userFilterAttrs...)
	if narrowed {
		switch eq.Attr {
		case attrUserName:
			filter.UserName = eq.Value
		case attrExternalID:
			filter.ExternalID = eq.Value
		case attrEmailsValue:
			filter.Email = eq.Value
		}
	}

	base := a.baseURL()

	var (
		total int
		page  []*scim.User
	)

	if req.Filter == nil || (narrowed && eq.Exact && slices.Contains(exactUserAttrs, eq.Attr)) {
		users, n, err := a.State.ListSCIMUsers(filter, req.StartIndex, req.Count)
		if err != nil {
			writeError(w, r, err)

			return
		}

		total = int(n)

		for i := range users {
			page = append(page, toSCIMUser(base, &users[i]))
		}
	} else {
		users, _, err := a.State.ListSCIMUsers(filter, 1, math.MaxInt32)
		if err != nil {
			writeError(w, r, err)

			return
		}

		var matched []*scim.User

		for i := range users {
			u := toSCIMUser(base, &users[i])

			ok, err := scim.Match(req.Filter, u)
			if err != nil {
				writeError(w, r, err)

				return
			}

			if ok {
				matched = append(matched, u)
			}
		}

		total = len(matched)
		page = scim.Paginate(req, matched)
	}

	resources := make([]any, 0, len(page))

	for _, u := range page {
		v, err := scim.Project(u, req.Attributes, req.ExcludedAttributes)
		if err != nil {
			writeError(w, r, err)

			return
		}

		resources = append(resources, v)
	}

	_ = scim.WriteJSON(w, http.StatusOK, scim.NewListResponse(req, total, resources))
}

func (a *api) getUser(w http.ResponseWriter, r *http.Request) {
	uid, err := userID(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	proj, err := parseProjection(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	u, err := a.State.GetSCIMUser(uid)
	if err != nil {
		writeError(w, r, userError(err))

		return
	}

	out := toSCIMUser(a.baseURL(), u)
	writeResource(w, proj, http.StatusOK, out.Meta.Location, out)
}

func (a *api) createUser(w http.ResponseWriter, r *http.Request) {
	proj, err := parseProjection(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	in, err := scim.DecodeUser(r.Body)
	if err == nil {
		err = in.Validate()
	}

	if err != nil {
		writeError(w, r, err)

		return
	}

	u, c, err := a.State.CreateSCIMUser(attributesFromUser(in, true), a.Cfg.SCIM.AdoptExistingUsers)
	a.broadcast(c)

	if err != nil && !committed(r, err) {
		writeError(w, r, userError(err))

		return
	}

	log.Info().EmbedObject(principal(r)).Uint(zf.UserID, u.ID).
		Str(zf.UserName, u.SCIMUserName.String).Bool(zf.UserSuspended, u.IsSuspended()).
		Msg("scim user provisioned")

	out := toSCIMUser(a.baseURL(), u)
	writeResource(w, proj, http.StatusCreated, out.Meta.Location, out)
}

func (a *api) replaceUser(w http.ResponseWriter, r *http.Request) {
	uid, err := userID(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	proj, err := parseProjection(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	in, err := scim.DecodeUser(r.Body)
	if err == nil {
		err = in.Validate()
	}

	if err != nil {
		writeError(w, r, err)

		return
	}

	// PUT replaces every attribute but an omitted active, which keeps the
	// stored state (see the package documentation).
	u, c, err := a.State.PatchSCIMUser(uid, func(attrs *types.SCIMUserAttributes) error {
		*attrs = attributesFromUser(in, attrs.Active)

		return nil
	})
	a.broadcast(c)

	if err != nil && !committed(r, err) {
		writeError(w, r, userError(err))

		return
	}

	log.Info().EmbedObject(principal(r)).Uint(zf.UserID, u.ID).
		Bool(zf.UserSuspended, u.IsSuspended()).Msg("scim user replaced")

	out := toSCIMUser(a.baseURL(), u)
	writeResource(w, proj, http.StatusOK, out.Meta.Location, out)
}

func (a *api) patchUser(w http.ResponseWriter, r *http.Request) {
	uid, err := userID(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	proj, err := parseProjection(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	req, err := scim.DecodePatch(r.Body)
	if err != nil {
		writeError(w, r, err)

		return
	}

	ops, err := scim.NormalizeUserPatch(req)
	if err != nil {
		writeError(w, r, err)

		return
	}

	logIgnored(r, ops)

	// The operations apply to the attributes read in the write
	// transaction, so a concurrent write cannot be lost.
	u, c, err := a.State.PatchSCIMUser(uid, func(attrs *types.SCIMUserAttributes) error {
		su := userFromAttributes(*attrs)

		err := scim.ApplyUserPatch(su, ops)
		if err != nil {
			return err
		}

		*attrs = attributesFromUser(su, attrs.Active)

		return nil
	})
	a.broadcast(c)

	if err != nil && !committed(r, err) {
		writeError(w, r, userError(err))

		return
	}

	log.Info().EmbedObject(principal(r)).Uint(zf.UserID, u.ID).
		Bool(zf.UserSuspended, u.IsSuspended()).Msg("scim user patched")

	out := toSCIMUser(a.baseURL(), u)
	writeResource(w, proj, http.StatusOK, out.Meta.Location, out)
}

func (a *api) deleteUser(w http.ResponseWriter, r *http.Request) {
	uid, err := userID(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	// Changes describe what was already deleted, even on error: they
	// must be sent regardless.
	changes, err := a.State.DeleteSCIMUser(uid)
	a.broadcast(changes...)

	if err != nil {
		writeError(w, r, userError(err))

		return
	}

	log.Info().EmbedObject(principal(r)).Uint64(zf.UserID, uint64(uid)).Msg("scim user deprovisioned")

	w.WriteHeader(http.StatusNoContent)
}

// logIgnored logs the PATCH operations that have no effect, such as
// enterprise extension attributes, for an operator wondering why a mapped
// attribute does not show up.
func logIgnored(r *http.Request, ops []scim.Operation) {
	for _, op := range ops {
		if ig, ok := op.(scim.IgnoredAttribute); ok {
			log.Debug().Str(zf.Path, r.URL.Path).Str(zf.SCIMIgnoredOp, ig.String()).
				Msg("scim patch operation ignored")
		}
	}
}
