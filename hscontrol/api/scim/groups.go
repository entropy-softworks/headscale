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

const attrMembers = "members"

// groupError maps the persistence errors of a group endpoint to SCIM errors.
// A missing user here is a member reference to something that is not a SCIM
// user: a bad value, not a missing resource.
func groupError(err error) *scim.Error {
	switch {
	case errors.Is(err, hsdb.ErrGroupNotFound):
		return scim.MapError(err, scim.ErrorMapping{Match: hsdb.ErrGroupNotFound, Result: scim.NotFound("group not found")})
	case errors.Is(err, hsdb.ErrUserNotFound):
		return scim.MapError(err, scim.ErrorMapping{
			Match:  hsdb.ErrUserNotFound,
			Result: scim.InvalidValue("members must be provisioned users: %s", err),
		})
	case errors.Is(err, hsdb.ErrSCIMInvalid):
		return scim.MapError(err, scim.ErrorMapping{
			Match:  hsdb.ErrSCIMInvalid,
			Result: scim.InvalidValue("%s", strings.TrimPrefix(err.Error(), "scim: ")),
		})
	}

	return scim.MapError(err, scim.ErrorMapping{
		Match:  hsdb.ErrSCIMConflict,
		Result: scim.Uniqueness("the displayName or externalId is already held by another group"),
	})
}

// groupDisplayName is the displayName as the client sent it, or for a group
// without one the unqualified name.
func groupDisplayName(g *types.Group) string {
	if g.DisplayName != "" {
		return g.DisplayName
	}

	name, _, _ := strings.Cut(g.Name, "@")

	return name
}

// toSCIMGroup renders a stored group with its member ids. users, when not
// nil, supplies the members' display.
func toSCIMGroup(base string, g *types.Group, members []types.UserID, users map[types.UserID]*types.User) *scim.Group {
	id := formatID(g.ID)
	out := &scim.Group{
		ID:          id,
		ExternalID:  g.ExternalID.String,
		DisplayName: groupDisplayName(g),
		Meta: &scim.Meta{
			ResourceType: scim.ResourceTypeGroup,
			Created:      g.CreatedAt.UTC(),
			LastModified: g.UpdatedAt.UTC(),
			Location:     scim.GroupLocation(base, id),
		},
	}

	for _, uid := range members {
		mid := formatID(uid)
		m := scim.Member{Value: mid, Ref: scim.UserLocation(base, mid), Type: scim.ResourceTypeUser}

		if u, ok := users[uid]; ok {
			m.Display = cmp.Or(u.SCIMDisplayName, u.SCIMUserName.String)
		}

		out.Members = append(out.Members, m)
	}

	return out
}

// memberDirectory returns the member users, by id, for rendering member
// display names; nil when there are no members to render.
func (a *api) memberDirectory(members map[uint][]types.UserID) (map[types.UserID]*types.User, error) {
	if len(members) == 0 {
		return nil, nil //nolint:nilnil // no directory is needed
	}

	var ids []types.UserID
	for _, ms := range members {
		ids = append(ids, ms...)
	}

	slices.Sort(ids)

	users, err := a.State.ListSCIMUsersByID(slices.Compact(ids)...)
	if err != nil {
		return nil, err
	}

	dir := make(map[types.UserID]*types.User, len(users))
	for i := range users {
		dir[types.UserID(users[i].ID)] = &users[i]
	}

	return dir, nil
}

// memberIDs converts member values to user ids. With strict, a value that
// is not a user id is invalidValue; otherwise it is dropped (removing
// something that cannot be a member is a no-op).
func memberIDs(values []string, strict bool) ([]types.UserID, error) {
	ids := make([]types.UserID, 0, len(values))

	for _, v := range values {
		id, ok := parseID(strings.TrimSpace(v))
		if !ok {
			if strict {
				return nil, scim.InvalidValue("member %q is not a user id", v)
			}

			continue
		}

		ids = append(ids, types.UserID(id))
	}

	return ids, nil
}

func groupID(r *http.Request) (uint, error) {
	id, ok := parseID(chi.URLParam(r, "id"))
	if !ok {
		return 0, scim.NotFound("group not found")
	}

	return id, nil
}

// renderGroup loads what the request's projection needs of the group and
// writes it.
func (a *api) renderGroup(w http.ResponseWriter, r *http.Request, p projection, status int, g *types.Group) {
	var (
		members map[uint][]types.UserID
		users   map[types.UserID]*types.User
		err     error
	)

	if wantsAttribute(p.attrs, p.excluded, attrMembers) {
		members, err = a.State.SCIMGroupMembers(g.ID)
		if err == nil {
			users, err = a.memberDirectory(members)
		}

		if err != nil {
			writeError(w, r, err)

			return
		}
	}

	out := toSCIMGroup(a.baseURL(), g, members[g.ID], users)
	writeResource(w, p, status, out.Meta.Location, out)
}

// groupFilterAttrs are the attributes a group list can look up in the
// database. Only externalId compares there exactly as scim.Match does:
// displayName compares as the qualified, ASCII-folded group name.
var groupFilterAttrs = []string{attrDisplayName, attrExternalID}

func (a *api) listGroups(w http.ResponseWriter, r *http.Request) {
	req, err := scim.ParseListRequest(r.URL.Query())
	if err != nil {
		writeError(w, r, err)

		return
	}

	var filter hsdb.SCIMGroupFilter

	eq, narrowed := scim.ExtractEquality(req.Filter, groupFilterAttrs...)
	if narrowed {
		switch eq.Attr {
		case attrDisplayName:
			filter.DisplayName = eq.Value
		case attrExternalID:
			filter.ExternalID = eq.Value
		}
	}

	var (
		total int
		page  []types.Group
	)

	withMembers := wantsAttribute(req.Attributes, req.ExcludedAttributes, attrMembers)

	var members map[uint][]types.UserID

	if req.Filter == nil || (narrowed && eq.Exact && eq.Attr == attrExternalID) {
		groups, n, err := a.State.ListSCIMGroups(a.groupsDomain(), filter, req.StartIndex, req.Count)
		if err != nil {
			writeError(w, r, groupError(err))

			return
		}

		total, page = int(n), groups
	} else {
		// Filters may test membership (Entra ID checks it with
		// "id eq … and members eq …"), so match with the members.
		groups, _, err := a.State.ListSCIMGroups(a.groupsDomain(), filter, 1, math.MaxInt32)
		if err == nil {
			members, err = a.State.SCIMGroupMembers(groupIDs(groups)...)
		}

		if err != nil {
			writeError(w, r, groupError(err))

			return
		}

		base := a.baseURL()

		var matched []types.Group

		for i := range groups {
			ok, err := scim.Match(req.Filter, toSCIMGroup(base, &groups[i], members[groups[i].ID], nil))
			if err != nil {
				writeError(w, r, err)

				return
			}

			if ok {
				matched = append(matched, groups[i])
			}
		}

		total, page = len(matched), scim.Paginate(req, matched)
	}

	var users map[types.UserID]*types.User

	if withMembers && len(page) > 0 {
		members, err = a.State.SCIMGroupMembers(groupIDs(page)...)
		if err == nil {
			users, err = a.memberDirectory(members)
		}

		if err != nil {
			writeError(w, r, err)

			return
		}
	}

	base := a.baseURL()
	resources := make([]any, 0, len(page))

	for i := range page {
		var ms []types.UserID
		if withMembers {
			ms = members[page[i].ID]
		}

		v, err := scim.Project(toSCIMGroup(base, &page[i], ms, users), req.Attributes, req.ExcludedAttributes)
		if err != nil {
			writeError(w, r, err)

			return
		}

		resources = append(resources, v)
	}

	_ = scim.WriteJSON(w, http.StatusOK, scim.NewListResponse(req, total, resources))
}

func groupIDs(groups []types.Group) []uint {
	ids := make([]uint, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}

	return ids
}

func (a *api) getGroup(w http.ResponseWriter, r *http.Request) {
	gid, err := groupID(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	proj, err := parseProjection(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	g, err := a.State.GetSCIMGroup(gid)
	if err != nil {
		writeError(w, r, groupError(err))

		return
	}

	a.renderGroup(w, r, proj, http.StatusOK, g)
}

// decodeGroup decodes and validates a POST or PUT body.
func decodeGroup(r *http.Request) (*scim.Group, []types.UserID, error) {
	in, err := scim.DecodeGroup(r.Body)
	if err != nil {
		return nil, nil, err
	}

	err = in.Validate()
	if err != nil {
		return nil, nil, err
	}

	members, err := memberIDs(in.MemberIDs(), true)
	if err != nil {
		return nil, nil, err
	}

	return in, members, nil
}

func (a *api) createGroup(w http.ResponseWriter, r *http.Request) {
	proj, err := parseProjection(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	in, members, err := decodeGroup(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	g, c, err := a.State.CreateSCIMGroup(a.groupsDomain(), in.DisplayName, in.ExternalID, members)
	a.broadcast(c)

	if err != nil && !committed(r, err) {
		writeError(w, r, groupError(err))

		return
	}

	log.Info().EmbedObject(principal(r)).Uint(zf.GroupID, g.ID).Str(zf.GroupName, g.Name).
		Int(zf.SCIMResourceCount, len(members)).Msg("scim group provisioned")

	a.renderGroup(w, r, proj, http.StatusCreated, g)
}

func (a *api) replaceGroup(w http.ResponseWriter, r *http.Request) {
	gid, err := groupID(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	proj, err := parseProjection(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	in, members, err := decodeGroup(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	g, c, err := a.State.UpdateSCIMGroup(a.groupsDomain(), gid,
		types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: in.DisplayName},
		types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: in.ExternalID},
		types.SCIMGroupOp{Kind: types.SCIMGroupReplaceMembers, Members: members},
	)
	a.broadcast(c)

	if err != nil && !committed(r, err) {
		writeError(w, r, groupError(err))

		return
	}

	log.Info().EmbedObject(principal(r)).Uint(zf.GroupID, g.ID).Str(zf.GroupName, g.Name).
		Int(zf.SCIMResourceCount, len(members)).Msg("scim group replaced")

	a.renderGroup(w, r, proj, http.StatusOK, g)
}

// groupOps translates normalised PATCH operations, already validated by
// scim.ApplyGroupPatch, to state operations, in order.
func groupOps(ops []scim.Operation) ([]types.SCIMGroupOp, error) {
	var out []types.SCIMGroupOp

	for _, op := range ops {
		var (
			next types.SCIMGroupOp
			err  error
		)

		switch o := op.(type) {
		case scim.SetAttribute:
			v, _ := o.Value.(string)

			switch o.Path.String() {
			case attrDisplayName:
				next = types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: v}
			case attrExternalID:
				next = types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: v}
			default:
				return nil, scim.InvalidPath("unsupported attribute %q", o.Path)
			}
		case scim.RemoveAttribute:
			if o.Path.String() != attrExternalID {
				return nil, scim.InvalidPath("cannot remove %q", o.Path)
			}

			next = types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID}
		case scim.AddMembers:
			next.Kind = types.SCIMGroupAddMembers
			next.Members, err = memberIDs(o.IDs, true)
		case scim.RemoveMembers:
			next.Kind = types.SCIMGroupRemoveMembers
			next.Members, err = memberIDs(o.IDs, false)
		case scim.ReplaceMembers:
			next.Kind = types.SCIMGroupReplaceMembers
			next.Members, err = memberIDs(o.IDs, true)
		case scim.IgnoredAttribute:
			continue
		default:
			return nil, scim.InvalidPath("unsupported operation %s", op)
		}

		if err != nil {
			return nil, err
		}

		out = append(out, next)
	}

	return out, nil
}

func (a *api) patchGroup(w http.ResponseWriter, r *http.Request) {
	gid, err := groupID(r)
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

	ops, err := scim.NormalizeGroupPatch(req)
	if err != nil {
		writeError(w, r, err)

		return
	}

	logIgnored(r, ops)

	current, err := a.State.GetSCIMGroup(gid)
	if err != nil {
		writeError(w, r, groupError(err))

		return
	}

	members, err := a.State.SCIMGroupMembers(gid)
	if err != nil {
		writeError(w, r, err)

		return
	}

	// Validate against the current group: a PATCH may not remove the
	// displayName or touch attributes groups do not have.
	_, err = scim.ApplyGroupPatch(toSCIMGroup(a.baseURL(), current, members[gid], nil), ops)
	if err != nil {
		writeError(w, r, err)

		return
	}

	stateOps, err := groupOps(ops)
	if err != nil {
		writeError(w, r, err)

		return
	}

	g := current

	if len(stateOps) > 0 {
		updated, c, err := a.State.UpdateSCIMGroup(a.groupsDomain(), gid, stateOps...)
		a.broadcast(c)

		if err != nil && !committed(r, err) {
			writeError(w, r, groupError(err))

			return
		}

		g = updated
	}

	log.Info().EmbedObject(principal(r)).Uint(zf.GroupID, g.ID).Str(zf.GroupName, g.Name).
		Int(zf.SCIMResourceCount, len(stateOps)).Msg("scim group patched")

	if !proj.isSet() {
		w.WriteHeader(http.StatusNoContent)

		return
	}

	a.renderGroup(w, r, proj, http.StatusOK, g)
}

func (a *api) deleteGroup(w http.ResponseWriter, r *http.Request) {
	gid, err := groupID(r)
	if err != nil {
		writeError(w, r, err)

		return
	}

	c, err := a.State.DeleteSCIMGroup(gid)
	a.broadcast(c)

	if err != nil && !committed(r, err) {
		writeError(w, r, groupError(err))

		return
	}

	log.Info().EmbedObject(principal(r)).Uint(zf.GroupID, gid).Msg("scim group deleted")

	w.WriteHeader(http.StatusNoContent)
}
