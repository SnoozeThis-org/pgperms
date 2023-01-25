package pgperms

// Config is the YAML format.
type Config struct {
	IgnoreSuperuserGrants *bool `yaml:"ignore_superuser_grants,omitempty"`

	Roles               map[string]RoleAttributes
	TombstonedRoles     []string `yaml:"tombstoned_roles,omitempty"`
	Databases           []string
	TombstonedDatabases []string `yaml:"tombstoned_databases,omitempty"`
	Schemas             []string
	TombstonedSchemas   []string `yaml:"tombstoned_schemas,omitempty"`

	DatabasePrivileges []GenericPrivilege `yaml:"database_privileges,omitempty"`
	SchemaPrivileges   []GenericPrivilege `yaml:"schema_privileges,omitempty"`
	TablePrivileges    []GenericPrivilege `yaml:"table_privileges,omitempty"`
	SequencePrivileges []GenericPrivilege `yaml:"sequence_privileges,omitempty"`
	// ColumnPrivileges             []GenericPrivilege `yaml:"column_privileges,omitempty"`
	// DomainPrivileges             []GenericPrivilege `yaml:"domain_privileges,omitempty"`
	// ForeignDataWrapperPrivileges []GenericPrivilege `yaml:"foreign_data_wrapper_privileges,omitempty"`
	// ForeignServerPrivileges      []GenericPrivilege `yaml:"foreign_server_privileges,omitempty"`
	// RoutinePrivileges            []GenericPrivilege `yaml:"routine_privileges,omitempty"`
	// LanguagePrivileges           []GenericPrivilege `yaml:"language_privileges,omitempty"`
	// LargeObjectPrivileges        []GenericPrivilege `yaml:"large_object_privileges,omitempty"`
	// TablespacePrivileges         []GenericPrivilege `yaml:"tablespace_privileges,omitempty"`
	TypePrivileges               []GenericPrivilege `yaml:"type_privileges,omitempty"`
}

func (c Config) GetIgnoreSuperuserGrants() bool {
	return c.IgnoreSuperuserGrants == nil || *c.IgnoreSuperuserGrants
}
