# ADPathFinder Data Model

## Domain

Represents the Active Directory domain.

Fields:

- Domain Name
- Domain SID
- Domain Controllers
- Domain Mode
- Forest Information

## User

Represents an Active Directory user.

Fields:

- Name
- Username
- Distinguished Name
- Enabled Status
- Password Never Expires
- Password Not Required
- Account Expiration
- Groups
- Privileged Status

## Group

Represents an Active Directory group.

Fields:

- Name
- Group Type
- Group Scope
- Members

## Computer

Represents an Active Directory computer.

Fields:

- Computer Name
- Operating System
- Enabled Status
- Distinguished Name
- Organizational Unit

## Finding

Represents a security issue discovered by ADPathFinder.

Fields:

- Finding ID
- Title
- Severity
- Affected Object
- Description
- Recommendation

## Relationship

Represents a connection between Active Directory objects.

Fields:

- Source Object
- Relationship Type
- Target Object
