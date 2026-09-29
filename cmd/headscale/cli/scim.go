package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

const (
	// DefaultSCIMTokenExpiry matches the API key default.
	DefaultSCIMTokenExpiry = DefaultAPIKeyExpiry

	// scimTokenNoExpiry is the --expiration value for a token that never
	// expires.
	scimTokenNoExpiry = "never"
)

var errSCIMTokenExpirationPast = errors.New("--expiration must be in the future")

func init() {
	rootCmd.AddCommand(scimCmd)
	scimCmd.AddCommand(scimTokensCmd)

	createSCIMTokenCmd.Flags().StringP("description", "d", "", "Human-readable description, e.g. the identity provider")
	createSCIMTokenCmd.Flags().StringP("expiration", "e", DefaultSCIMTokenExpiry,
		`Human-readable expiration of the token (e.g. 30d, 1y), or "`+scimTokenNoExpiry+`"`)
	scimTokensCmd.AddCommand(createSCIMTokenCmd)
	scimTokensCmd.AddCommand(listSCIMTokensCmd)
	scimTokensCmd.AddCommand(revokeSCIMTokenCmd)
	scimTokensCmd.AddCommand(deleteSCIMTokenCmd)

	scimCmd.AddCommand(scimUsersCmd)
	scimUsersCmd.AddCommand(listSCIMUsersCmd)

	scimCmd.AddCommand(scimGroupsCmd)
	scimGroupsCmd.AddCommand(listSCIMGroupsCmd)
	scimGroupsCmd.AddCommand(releaseSCIMGroupCmd)
}

var scimCmd = &cobra.Command{
	Use:   "scim",
	Short: "Manage SCIM provisioning",
}

var scimTokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Manage the bearer tokens identity providers use for SCIM provisioning",
	Long: `SCIM tokens authenticate an identity provider's SCIM client (the "Secret
Token" in Entra ID, the HTTP header token in Okta) to Headscale's SCIM
endpoints. They are accepted only there, never by the admin API.

An OAuth client created with "headscale oauth-clients create -s scim" can be
used instead by identity providers that support the client-credentials grant.`,
	Aliases: []string{"token"},
}

var createSCIMTokenCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a SCIM token",
	Long: `Create a SCIM bearer token. The token is shown ONCE on creation and cannot
be retrieved again; if you lose it, create a new one and revoke the old one.`,
	Aliases: []string{"c", cmdNew},
	Args:    cobra.NoArgs,
	RunE:    clientRunE(createSCIMToken),
}

var listSCIMTokensCmd = &cobra.Command{
	Use:     cmdList,
	Short:   "List SCIM tokens",
	Aliases: []string{"ls", cmdShow},
	Args:    cobra.NoArgs,
	RunE:    clientRunE(listSCIMTokens),
}

var revokeSCIMTokenCmd = &cobra.Command{
	Use:     "revoke ID",
	Short:   "Revoke a SCIM token; it stops authenticating but stays listed",
	Aliases: []string{cmdExpire},
	Args:    cobra.ExactArgs(1),
	RunE:    clientRunE(revokeSCIMToken),
}

var deleteSCIMTokenCmd = &cobra.Command{
	Use:     cmdDelete + " ID",
	Short:   "Delete a SCIM token permanently",
	Aliases: []string{"remove", aliasDel},
	Args:    cobra.ExactArgs(1),
	RunE:    clientRunE(deleteSCIMToken),
}

var scimUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Inspect the users provisioned through SCIM",
	Long: `Users provisioned through SCIM are managed by the identity provider: it
creates, updates, suspends (active=false) and deletes them. A provisioned user
is linked to their OIDC login at their first login. While SCIM is enabled,
"headscale users rename" and "headscale users destroy" refuse them; a
suspension set with "headscale users suspend" lasts until the identity
provider next sends the user's active state.`,
	Aliases: []string{"user"},
}

var listSCIMUsersCmd = &cobra.Command{
	Use:     cmdList,
	Short:   "List SCIM users",
	Aliases: []string{"ls", cmdShow},
	Args:    cobra.NoArgs,
	RunE:    clientRunE(listSCIMUsers),
}

var scimGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Manage the groups provisioned through SCIM",
	Long: `Groups provisioned through SCIM are referenced in the policy as
group:<displayName>@<domain>, and as group:<externalId>@<domain> when they
have an external id. SCIM alone decides their members: OIDC logins asserting
such a group in their groups claim do not grant it.`,
	Aliases: []string{"group"},
}

var listSCIMGroupsCmd = &cobra.Command{
	Use:     cmdList,
	Short:   "List SCIM groups",
	Aliases: []string{"ls", cmdShow},
	Args:    cobra.NoArgs,
	RunE:    clientRunE(listSCIMGroups),
}

var releaseSCIMGroupCmd = &cobra.Command{
	Use:   "release ID",
	Short: "Hand a SCIM group back to OIDC logins",
	Long: `Release a SCIM group, for when SCIM provisioning is turned off. Its SCIM
memberships and external id are removed at once; OIDC logins asserting the
group in their groups claim grant it again from their next login. The group
keeps its id and name, so policy references to group:<name> keep working,
while references to its external id alias stop matching.

Refused while scim.enabled is true: the identity provider still owns the
group and would provision it again. Disable SCIM first.`,
	Args: cobra.ExactArgs(1),
	RunE: clientRunE(releaseSCIMGroup),
}

func listSCIMUsers(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, _ []string) error {
	resp, err := client.ListScimUsersWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("listing scim users: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	users := resp.JSON200.ScimUsers

	return printListOutput(cmd, users, func() error {
		rows := make([][]string, 0, len(users))
		for _, u := range users {
			rows = append(rows, []string{
				u.Id,
				u.UserName,
				u.ExternalId,
				u.Email,
				u.Name,
				yesNo(u.Linked),
				activeOrSuspended(u.Suspended),
			})
		}

		return renderTable(
			[]string{"ID", "User name", "External ID", "Email", "Username", "Linked", "Status"},
			rows,
		)
	})
}

func listSCIMGroups(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, _ []string) error {
	resp, err := client.ListScimGroupsWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("listing scim groups: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	groups := resp.JSON200.ScimGroups

	return printListOutput(cmd, groups, func() error {
		rows := make([][]string, 0, len(groups))
		for _, g := range groups {
			rows = append(rows, []string{
				g.Id,
				g.DisplayName,
				g.PolicyReference,
				g.ExternalId,
				g.PolicyAlias,
				strconv.FormatInt(g.MemberCount, util.Base10),
				g.Source,
			})
		}

		return renderTable(
			[]string{"ID", "Display name", "Policy reference", "External ID", "Alias", "Members", "Source"},
			rows,
		)
	})
}

func releaseSCIMGroup(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], util.Base10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid scim group id %q", errMissingParameter, args[0])
	}

	idStr := strconv.FormatUint(id, util.Base10)

	if !confirmAction(cmd, fmt.Sprintf(
		"Release SCIM group %s? Its SCIM members lose it now. From then on, any user whose OIDC "+
			"groups claim asserts the group is granted it at their next login, so policies "+
			"referencing it follow the groups claim instead of SCIM.",
		idStr,
	)) {
		return printOutput(cmd, map[string]string{colResult: "Group not released"}, "Group not released")
	}

	resp, err := client.ReleaseScimGroupWithResponse(ctx, idStr)
	if err != nil {
		return fmt.Errorf("releasing scim group: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	done := "SCIM group " + idStr + " released"

	return printOutput(cmd, map[string]string{colResult: done}, done)
}

// yesNo renders a flag as a table cell.
func yesNo(b bool) string {
	if b {
		return "yes"
	}

	return "no"
}

// activeOrSuspended renders a user's suspension as a table cell.
func activeOrSuspended(suspended bool) string {
	if suspended {
		return pterm.LightRed("suspended")
	}

	return pterm.LightGreen("active")
}

// scimTokenExpiration reads --expiration: nil for "never" (any case),
// otherwise now plus the duration, which must be positive.
func scimTokenExpiration(cmd *cobra.Command) (*time.Time, error) {
	value, _ := cmd.Flags().GetString("expiration")
	if strings.EqualFold(value, scimTokenNoExpiry) {
		return nil, nil //nolint:nilnil // nil expiration means the token never expires
	}

	expiry, err := expirationFromFlag(cmd)
	if err != nil {
		return nil, err
	}

	if !expiry.After(time.Now()) {
		return nil, fmt.Errorf("%w: %q", errSCIMTokenExpirationPast, value)
	}

	return &expiry, nil
}

func createSCIMToken(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, _ []string) error {
	expiration, err := scimTokenExpiration(cmd)
	if err != nil {
		return err
	}

	description, _ := cmd.Flags().GetString("description")

	resp, err := client.CreateScimTokenWithResponse(ctx, clientv1.CreateScimTokenJSONRequestBody{
		Description: &description,
		Expiration:  expiration,
	})
	if err != nil {
		return fmt.Errorf("creating scim token: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	return printOutput(cmd, resp.JSON200, resp.JSON200.Token)
}

func listSCIMTokens(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, _ []string) error {
	resp, err := client.ListScimTokensWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("listing scim tokens: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	tokens := resp.JSON200.ScimTokens

	return printListOutput(cmd, tokens, func() error {
		rows := make([][]string, 0, len(tokens))
		for _, tok := range tokens {
			rows = append(rows, []string{
				tok.Id,
				tok.Prefix,
				tok.Description,
				optionalTime(tok.Expiration, true),
				optionalTime(tok.LastSeen, false),
				optionalTime(tok.Revoked, false),
				optionalTime(tok.CreatedAt, false),
			})
		}

		return renderTable(
			[]string{"ID", "Prefix", "Description", colExpiration, "Last seen", "Revoked", colCreated},
			rows,
		)
	})
}

func revokeSCIMToken(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
	id, err := scimTokenIDArg(args)
	if err != nil {
		return err
	}

	resp, err := client.RevokeScimTokenWithResponse(ctx, id)
	if err != nil {
		return fmt.Errorf("revoking scim token: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	return printOutput(cmd, resp.JSON200, "SCIM token "+id+" revoked")
}

func deleteSCIMToken(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
	id, err := scimTokenIDArg(args)
	if err != nil {
		return err
	}

	resp, err := client.DeleteScimTokenWithResponse(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting scim token: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	return printOutput(cmd, resp.JSON200, "SCIM token "+id+" deleted")
}

// scimTokenIDArg validates the positional token id before it is sent.
func scimTokenIDArg(args []string) (string, error) {
	id, err := strconv.ParseUint(args[0], util.Base10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: invalid scim token id %q", errMissingParameter, args[0])
	}

	return strconv.FormatUint(id, util.Base10), nil
}

// optionalTime renders a nullable timestamp, "-" when unset. colour marks
// future times green and past ones red, as for expirations.
func optionalTime(t *time.Time, colour bool) string {
	if t == nil {
		return "-"
	}

	if colour {
		return ColourTime(*t)
	}

	return t.Format(HeadscaleDateTimeFormat)
}
