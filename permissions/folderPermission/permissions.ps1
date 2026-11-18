#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-FolderPermission
# List calendar folder permissions (for the Default user) as permissions
# PowerShell V2
#####################################################

# Each permission sets the access right of mailboxFolderUser on the calendar folder of the account's mailbox.
# Options for mailboxFolderAccessRight: AvailabilityOnly, LimitedDetails, Reviewer, Editor (see Set-MailboxFolderPermission)
$outputContext.Permissions.Add(
    @{
        displayName    = 'Mailbox folder permissions - Availability only'
        identification = @{
            Id                       = '1' # Must be unique
            mailboxFolderUser        = 'Default'
            mailboxFolderAccessRight = 'AvailabilityOnly'
        }
    }
)

$outputContext.Permissions.Add(
    @{
        displayName    = 'Mailbox folder permissions - Limited details'
        identification = @{
            Id                       = '2' # Must be unique
            mailboxFolderUser        = 'Default'
            mailboxFolderAccessRight = 'LimitedDetails'
        }
    }
)

$outputContext.Permissions.Add(
    @{
        displayName    = 'Mailbox folder permissions - Reviewer'
        identification = @{
            Id                       = '3' # Must be unique
            mailboxFolderUser        = 'Default'
            mailboxFolderAccessRight = 'Reviewer'
        }
    }
)

$outputContext.Permissions.Add(
    @{
        displayName    = 'Mailbox folder permissions - Editor'
        identification = @{
            Id                       = '4' # Must be unique
            mailboxFolderUser        = 'Default'
            mailboxFolderAccessRight = 'Editor'
        }
    }
)
