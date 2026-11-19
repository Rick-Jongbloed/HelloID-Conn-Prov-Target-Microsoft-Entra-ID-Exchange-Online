# Educational teams (Microsoft Teams for education)

Manages the **members** (for example students) and **owners** (for example teachers) of educational teams in Microsoft Teams, and creates those teams per school year. The scripts work on the Microsoft 365 groups behind the teams via Microsoft Graph; they do not use the Education API (`/education/...`) or School Data Sync.

Use it as a separate target system next to the Entra ID connector, with the same app registration and the extra settings below. The accounts are managed by the Entra ID connector; this target system only correlates them.

## Table of contents

- [Supported features](#supported-features)
- [How it works](#how-it-works)
  - [Educational teams and the school year](#educational-teams-and-the-school-year)
  - [Scripts](#scripts)
  - [Static permissions](#static-permissions)
  - [Dynamic permissions (sub permissions)](#dynamic-permissions-sub-permissions)
  - [Entitlement import](#entitlement-import)
  - [Resources: creating the teams](#resources-creating-the-teams)
- [When to use what](#when-to-use-what)
- [Configuration](#configuration)
- [Required permissions](#required-permissions)
- [Remarks](#remarks)
- [Development resources](#development-resources)

## Supported features

| Feature                                   | Supported | Actions                             | Remarks            |
| ----------------------------------------- | --------- | ----------------------------------- | ------------------ |
| **Account Lifecycle**                     | ✅         | Correlate                           |                    |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke             | Static and Dynamic |
| **Resources**                             | ✅         | Creation of educational teams       | `withActivationButton`: education tenant only |
| **Entitlement Import: Permissions**       | ✅         | -                                   |                    |
| **Governance Reconciliation Resolutions** | ✅⚠️        | -                                   | Permissions only; accounts depend on the Entra ID connector |

## How it works

### Educational teams and the school year

A team is in scope when it is a Microsoft 365 group with a team (`resourceProvisioningOptions` contains `Team`) and its display name ends with `_<school year>`. The name convention is:

```
<prefix>_<code>_<school year>        for example  Klas_1A_2627, Les_WIS-3B_2627
```

- **prefix**: one of the configured prefixes (`classTeamPrefix`, `lessonTeamPrefix`, `subjectTeamPrefix`).
- **code**: the code of the class or lesson group from the source system (for example the department external id). Special characters are removed (`Get-SanitizedGroupName`).
- **school year**: calculated by `Get-SchoolYear` in every script. From August the new school year starts: in November 2026 it is `2627`, in March 2027 also `2627`, from August 2027 `2728`. By default 2 digits per year without separator; `$schoolYearLength` and `$schoolYearSeperator` in the function change this (for example `2026-2027`). Keep these the same in all scripts.

Because the school year is part of the name, the teams of the previous school year are no longer in scope from August: they are no longer listed as permissions and not imported.

### Scripts

| Folder / script | Action |
| --------------- | ------ |
| `members/permissions.ps1` and `owners/permissions.ps1` | Lists every team of the current school year as a permission (`Id` = object id of the group) |
| `members/grantPermission.ps1` | Adds the account as member (`POST /groups/{id}/members/$ref`). Already a member counts as success |
| `members/revokePermission.ps1` | Removes the account as member (`DELETE /groups/{id}/members/{id}/$ref`) |
| `owners/grantPermission.ps1` and `owners/revokePermission.ps1` | The same for owners (`/owners`) |
| `members/subPermissions.ps1` and `owners/subPermissions.ps1` | Grants and revokes teams dynamically, based on the contracts of the person |
| `members/import.ps1` and `owners/import.ps1` | Entitlement import of the static permissions |
| `members/importSubPermissions.ps1` and `owners/importSubPermissions.ps1` | Entitlement import of the dynamic permissions |
| `resources/educationalGroups/withoutActivationButton/resources.ps1` | Creates the teams directly with the `educationClass` template |
| `resources/educationalGroups/withActivationButton/resources.ps1` | Creates the groups first and upgrades them to an `educationClass` team afterwards |

### Static permissions

`permissions.ps1` lists every team of the current school year as a separate permission. A business rule (or a request in the self-service product) grants a specific team; `grantPermission.ps1` and `revokePermission.ps1` add or remove the account as member or owner of that one team.

### Dynamic permissions (sub permissions)

`subPermissions.ps1` determines the teams from the contracts of the person. For every contract in conditions:

1. The team name is `<classTeamPrefix>_<Department.ExternalId>_<school year>`, for example `Klas_1A_2627`.
2. The group is looked up by display name. Not found or more than one: an audit log, no grant.
3. Teams that are desired but not granted yet are granted; teams that were granted before (`CurrentPermissions`) but are no longer desired are revoked. Already a member or already removed counts as success.

One permission in HelloID (for example *EDU Teams - Members*) then covers all teams of the person. When the class of a student changes in the source system, the next update moves the student to the team of the new class.

> [!NOTE]
> The dynamic scripts use `classTeamPrefix` and `Department.ExternalId`. Adjust these lines when the classes or lesson groups are in another field of the contract, or when lesson or subject teams must be granted dynamically.

### Entitlement import

- `import.ps1` reads all teams of the current school year with their members (or owners) and returns them per team, for the static permissions.
- `importSubPermissions.ps1` returns the same memberships as sub permissions of one permission (*EDU Teams - Members* / *EDU Teams - Owners*), for the dynamic permissions. It searches the groups with `$search` on the school year in the display name.
- Both skip the account in `ownerGuid` (the technical owner that creates the teams), so it is not reported as a membership.
- Use only the import that matches the way the permissions are granted (static or dynamic), otherwise the same memberships are imported twice.

### Resources: creating the teams

The resource scripts create a team for every unique `ExternalId` in the resource data, with the name `<prefix>_<ExternalId>_<school year>`. A team that already exists (same display name) is correlated. At most 200 teams are created per run (`$maximumAmountToCreatePerRun`); at the start of a school year several runs are needed.

| Script | How the team is created | Prefix used |
| ------ | ----------------------- | ----------- |
| `withoutActivationButton` | One call: `POST /teams` with the `educationClass` template. The team is directly visible to the students. | `lessonTeamPrefix` |
| `withActivationButton` | First the Microsoft 365 group (`POST /groups`, with education class settings), then the upgrade to a team with the `educationClass` template (up to 3 attempts). The teacher activates the team before students see it; most schools use this. | `subjectTeamPrefix` |

> [!IMPORTANT]
> `withActivationButton` sets the education property `Education_ObjectType` on the group, which exists only in a Microsoft 365 **Education** tenant (A1/A3/A5 licenses). In another tenant the group is refused with *The following extension properties are not available: extension_..._Education_ObjectType*. `withoutActivationButton` (the `educationClass` template only) also worked in a test tenant without education licenses. The permission scripts work in any tenant, because they only use the group and its members and owners.

> [!IMPORTANT]
> The resource scripts and `subPermissions.ps1` use different prefixes by default (`lessonTeamPrefix` / `subjectTeamPrefix` versus `classTeamPrefix`). When the teams created by a resource script must be granted dynamically, use the same prefix in both scripts.

## When to use what

| Situation | Use |
| --------- | --- |
| Students must be member of the team of their class, automatically from the HR or student system | Resources (to create the teams per school year) + `members/subPermissions.ps1` + `members/importSubPermissions.ps1` |
| Mentors or teachers must be owner of the team of their class | `owners/subPermissions.ps1` (contract of the teacher points to the class) + `owners/importSubPermissions.ps1` |
| A few fixed teams, or teams that are requested and approved by hand | `permissions.ps1` + `grantPermission.ps1` / `revokePermission.ps1` + `import.ps1` (static) |
| The school creates the teams itself (for example with School Data Sync) and HelloID only manages memberships | Only the permission scripts; no resource scripts. The team names must follow the name convention above |
| The teams must not be visible to students before the teacher starts | `withActivationButton` |
| The teams must be usable directly | `withoutActivationButton` |
| Not an education tenant | The permission scripts, and `withoutActivationButton` to create the teams (or teams created in another way, named by the convention) |

## Configuration

The following settings are required on top of the Entra ID connector configuration (`configuration.json` in this folder).

| Setting | Description | Mandatory |
| ------- | ----------- | --------- |
| `classTeamPrefix` | Prefix of the class teams (default `Klas`), used by `subPermissions.ps1` | No |
| `lessonTeamPrefix` | Prefix of the lesson teams (default `Les`), used by `withoutActivationButton` | No |
| `subjectTeamPrefix` | Prefix of the subject teams (default `Vak`), used by `withActivationButton` | No |
| `ownerGuid` | Object id of the Entra ID account that is set as owner when a team is created (a team needs an owner). It is left out of the imports | Yes |

## Required permissions

API permissions (Microsoft Graph, application) for the permission scripts (`members/` and `owners/`):

| Permission                  | Used for                                                     |
| --------------------------- | ------------------------------------------------------------ |
| `GroupMember.ReadWrite.All` | Listing the groups and members, adding and removing members  |
| `Group.ReadWrite.All`       | Adding and removing owners (`owners/` only)                  |
| `User.Read.All`             | Reading the account. Included in `User.ReadWrite.All` of the account scripts |

API permissions (Microsoft Graph, application) for the resource scripts (`resources/educationalGroups/`):

| Permission                   | Used for                                                    |
| ---------------------------- | ----------------------------------------------------------- |
| `Group.ReadWrite.All`        | Listing and creating the Microsoft 365 groups               |
| `Team.Create`                | Creating the educational teams from the groups              |
| `TeamSettings.ReadWrite.All` | Team settings of the educational teams                      |
| `TeamMember.ReadWrite.All`   | Team membership of the owner                                |

## Remarks

### Performance

> [!IMPORTANT]
> Creating Microsoft 365 groups and teams with the `educationClass` template takes time in Entra ID. Therefore `withActivationButton` creates the groups first and upgrades them to teams afterwards; combined in one step HelloID times out and the groups are not created.

### Filter the Entra ID group permissions

The educational teams are also Microsoft 365 groups, so the `groups` permissions of the Entra ID connector list them as well. Add a filter to the group scripts of the Entra ID connector (for example on the school year in the display name), so a team is managed by one target system only and is not reconciled by both.

### Removing an owner

A team always needs an owner. Revoking the last owner of a team fails; the technical owner (`ownerGuid`) prevents this for teams created by the resource scripts.

## Development resources

### API endpoints

| Endpoint | Description |
| -------- | ----------- |
| `/groups` | Listing the Microsoft 365 groups, looking up a team by display name, creating groups (`withActivationButton`) |
| `/groups/{id}/members` and `/groups/{id}/members/$ref` | Listing, adding and removing members |
| `/groups/{id}/owners` and `/groups/{id}/owners/$ref` | Listing, adding and removing owners |
| `/$batch` | Reading the members or owners of many groups in one request (imports) |
| `/teams` | Listing the teams, creating a team or upgrading a group to a team |
| `/teamsTemplates('educationClass')` | Template of the educational teams |

For more information:

- [Create team (Microsoft Graph)](https://learn.microsoft.com/en-us/graph/api/team-post?view=graph-rest-1.0)
- [Add members to a group](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0) and [Add owners to a group](https://learn.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0)
