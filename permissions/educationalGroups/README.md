# Microsoft Teams Educational Class

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                             | Remarks            |
| ----------------------------------------- | --------- | ----------------------------------- | ------------------ |
| **Account Lifecycle**                     | ✅         | Correlate                           |                    |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke             | Static and Dynamic |
| **Resources**                             | ✅         | Creation of M365 educational groups |                    |
| **Entitlement Import: Permissions**       | ✅         | -                                   |                    |
| **Governance Reconciliation Resolutions** | ✅⚠️        | -                                   |                    |

### ⚠️ Governance Reconciliation Resolutions

Governance reconciliation is supported for permissions only. Accounts are dependent on the use of the Entra ID connector

# HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.ReadWrite.All`
  - `Group.ReadWrite.All`
  - `GroupMember.ReadWrite.All`
  - `GroupMember.ReadWrite.All`
  - `Team.Create`
  - `Team.ReadBasic.All`
  - `TeamMember.ReadWrite.All`
  - `TeamSettings.ReadWrite.All`

## Configuration

The following extra settings are required to on top of the Entra ID connector configuration.

| Setting       | Description                                                                                                            | Mandatory |
| ------------- | ---------------------------------------------------------------------------------------------------------------------- | --------- |
| ClassPrefix   | Prefix for Class Educational Teams (Klassen)                                                                           | No        |
| LessonPrefix  | Prefix for Lesson Educational Teams (Lessen)                                                                           | No        |
| SubjectPrefix | Prefix for Subject Educational Teams (Vakken)                                                                          | No        |
| OwnerGuid     | GUID of user in EntraID which is used to create the groups and set as owner. Owner is mandatory for creating the Teams | Yes       |

## Remarks

### Performance Issues

> [!IMPORTANT]
> Due to process duration within Entra ID of creating M365 Groups and Teams with the Educational Class template, some design choices have been made. Groups are created separated from applying the template. When these actions are combined in the resource scripts, HelloID will timeout and groups are not created.

### Resources

Within the connector M365 groups are created with specific settings. These settings are needed to convert the groups to MS Educational Teams. To stay within the performance limits a maximum of groups to be created in one run is set to 200.

Creation of Teams is possible in two ways, with or without an activation button for the teacher. When creating with the availability of an activation button, the Educational Team will be visible to students after a teacher manually activates the Team for use. This is used by most schools.

> [!IMPORTANT]
> On the start of a new school year multiple runs are necessary before all groups are created. Per run a maximum of 200 groups will be created.

### School year

In all scripts the school year is calculated based on current and next school year. This value is used in the name of the groups and teams and can be used as filter in the permissions shown in the business rules and in other scripts.

### Filter Entra ID permissions

When combining this target connector with the Entra ID connector, it's advised to implement filters in the group-scripts. Otherwise the Educational groups will also be available in the Entra ID permissions. To prevent that groups are available in both targets and are used for reconciliation in both targets, add some filtering.

<!--
Provide remarks on special aspects of the code or the internal workings of the connector.

**Please ensure to use `###` tags for H3 headings for each remark.**

Example:

### GET Account API Limitation
- **No GET Endpoint**: The API does not support a GET request to retrieve account details. You may need to use alternative methods or endpoints to access account information, such as using a POST request with appropriate parameters.

### Correlation Based on Email Address
- **Email Address Correlation**: The connector relies on email addresses to correlate and match records between systems. Ensure that email addresses are accurately maintained and consistent across systems to avoid issues with data synchronization and matching.
-->

## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint                           | Description                                                  |
| ---------------------------------- | ------------------------------------------------------------ |
| /users                             | Handle user information                                      |
| /users/{id}                        | Get or update specific user                                  |
| /users/{id}/authentication         | Handle authentication method                                 |
| /users/{id}/manager                | Get, set or remove user's manager                            |
| /groups                            | Handle group information                                     |
| /groups/{id}/members               | Get group members                                            |
| /teamsTemplates('educationalClass) | Template used for creation                                   |
| /teams                             | To upgrade an M365 created group to a Educational Class team |
