package pgperms

import (
	"sort"
	"strings"
)

// mergePrivileges tries to group privileges together, for fewer SQL statements and smaller config files.
func mergePrivileges(input []GenericPrivilege) []GenericPrivilege {
	if len(input) == 0 {
		return nil
	}
	t := input[0].targets()[0]
	// Combine all given privileges and merge all privs for the same [grantee, target, grantable] into a set of privileges.
	existing := map[string]map[string]map[bool]privilegeSet{}
	for _, o := range input {
		for _, grantee := range o.Roles {
			if existing[grantee] == nil {
				existing[grantee] = map[string]map[bool]privilegeSet{}
			}
			for _, target := range o.untypedTargets() {
				if existing[grantee][target] == nil {
					existing[grantee][target] = map[bool]privilegeSet{}
				}
				for _, priv := range o.Privileges {
					ps := existing[grantee][target][o.Grantable]
					ps.Add(priv)
					existing[grantee][target][o.Grantable] = ps
				}
			}
		}
	}
	groupAll := map[grantableAndPrivilegeSetAndTargets]targetsAndRoles{}
	for grantee, tmp1 := range existing {
		// Group privileges for the same [grantable, privilegeSet] together for all targets within a single user.
		groupTargets := map[grantableAndPrivilegeSet][]string{}
		for target, tmp2 := range tmp1 {
			for grantable, ps := range tmp2 {
				groupTargets[grantableAndPrivilegeSet{grantable, ps}] = append(groupTargets[grantableAndPrivilegeSet{grantable, ps}], target)
			}
		}
		for gaps, targets := range groupTargets {
			sort.Strings(targets)
			// Group privileges for the same [grantable, privilegeSet, targets] together across users.
			k := grantableAndPrivilegeSetAndTargets{
				grantable:     gaps.grantable,
				privilegeSet:  gaps.privilegeSet,
				joinedTargets: strings.Join(targets, "\x00"),
			}
			if v, ok := groupAll[k]; ok {
				v.roles = append(v.roles, grantee)
				groupAll[k] = v
			} else {
				groupAll[k] = targetsAndRoles{
					targets: targets,
					roles:   []string{grantee},
				}
			}
		}
	}
	// Unfold this back into a []GenericPrivilege.
	var ret []GenericPrivilege
	for gapsat, tar := range groupAll {
		gp := GenericPrivilege{
			Privileges: gapsat.privilegeSet.List(),
			Grantable:  gapsat.grantable,
			Roles:      tar.roles,
		}
		gp.set(t, tar.targets)
		ret = append(ret, gp)
	}
	return ret
}

type grantableAndPrivilegeSet struct {
	grantable    bool
	privilegeSet privilegeSet
}

type grantableAndPrivilegeSetAndTargets struct {
	grantable     bool
	privilegeSet  privilegeSet
	joinedTargets string
}

type targetsAndRoles struct {
	targets []string
	roles   []string
}
