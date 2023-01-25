# pgperms

pgperms allows you to manage your PostgreSQL permissions in a configuration file. This follows the configuration as code paradigm and allows you to declaratively manage your PostgreSQL grants.

## Installation

```shell
go install github.com/SnoozeThis-org/pgperms/cmd/pgperms@latest
```

or grab it from our [Releases](https://github.com/SnoozeThis-org/pgperms/releases/latest).

## Getting started

If you already have an existing PostgreSQL cluster running, you can create pgperms config file from that cluster through:

```shell
$ pgperms --dump --user postgres > pgperms.yaml
```

Then you can edit your config and see what changes need to be made:

```shell
$ pgperms --user postgres --config pgperms.yaml
```

And finally you can sync your config file to the cluster:

```shell
$ pgperms --user postgres --config pgperms.yaml --apply
```

The password can be read from your .pgpass, or prompted by using `-W` .

## Managing roles

pgperms is the source of truth for all roles defined in its config file. When syncing, it will make those roles have exactly the specified permissions.

Any roles not listed in the config file are unmanaged, and will be completely ignored by pgperms.

To delete users, you have to list them as tombstoned users. (If you were to simply remove them from the config file, they'd become unmanaged users instead of being dropped.)

```yaml
roles:
  yourname:
    password: SCRAM-SHA-256$4096:ICus8JAbG67BUVc+bifCBg==$3ULFbqx6ySVZJr51b6DOVQIbqy3GxrsHyxb/+JD0pag=:TJyct6ApBeiTdr+z7RP8CXtTOO5w+iK3NEervm9Ezb0=
    superuser: true
  rolegroup:
    login: false
  someonewithlotsofsettings:
    createdb: true
    createrole: true
    bypassrls: true
    inherit: true
    connectionlimit: 3
    valid_until: "2038-01-01 00:00:00"
    member_of: [rolegroup]
  replication:
    replication: true
tombstoned_roles:
- oldemployee
```

## Managing databases and schemas

Though not exactly permissions, pgperms can also create/drop databases and schemas for you. This is to make it easy to bootstrap a new cluster with pgperms. Pgperms can create databases/schemas for you and immediately set the correct permissions on them.

To delete databases/schemas, you have to list them as tombstoned. (If you were to simply remove them from the config file, they'd become unmanaged instead of being dropped.)

```yaml
databases:
- mydatabase
tombstoned_databases:
- unused_database

schemas:
- mydatabase.myschema
tombstoned_schemas:
- mydatabase.unused_schema
```

Permissions are configured like this:

```yaml
database_privileges:
  - roles: [rolegroup]
    privileges: [CONNECT]
    databases:
      - mydatabase
  - roles: [someonewithlotsofsettings]
    privileges: [CONNECT, TEMPORARY]
    databases:
      - mydatabase

schema_privileges:
  - roles: [rolegroup]
    privileges: [USAGE]
    schemas:
      - mydatabase.myschema
  - roles: [someonewithlotsofsettings]
    privileges: [CREATE, USAGE]
    schemas:
      - mydatabase.myschema
```

## Table permissions

Tables can't be created/dropped by pgperms. You can configure the permissions however.

You can use `*` as the table name to imply all tables in a schema.

You can also configure the permissions for views, materialized views, foreign tables and partitioned tables as if they were tables.

```yaml
table_privileges:
  - roles: [rolegroup]
    privileges: [SELECT, INSERT, UPDATE]
    tables:
      - mydatabase.myschema.mytable
      - mydatabase.otherschema.*
```

## Sequence permissions

Sequences can't be created/dropped by pgperms. You can configure the permissions however.

You can use `*` as the sequences name to imply all sequences in a schema.

```yaml
sequence_privileges:
  - roles: [rolegroup]
    privileges: [SELECT, UPDATE, USAGE]
    sequences:
      - mydatabase.otherschema.*
```

## Type and domain permissions

Types work similarly as the others. For the purposes of pgperms you should consider domains to simply be types.

## Contributions

We'll happily accept your contributions! There's still a lot of things not supported:

- Permissions on columns, foreign data wrappers, foreign servers, routines, languages, large objects or tablespaces.
- Set up default privileges so that newly created tables already have the correct permissions without having to run pgperms?
- A config setting to automatically manage all users (and thus delete any unlisted users without needing to tombstone them).
- More test cases

Development of pgperms is sponsored by [SnoozeThis](http://www.snoozethis.com/): a bot that can hold on to your blocked issues until they're actionable.
