import UserRepresentation from "@keycloak/keycloak-admin-client/lib/defs/userRepresentation";
import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownList,
  MenuToggle,
  ToolbarItem,
} from "@patternfly/react-core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useAdminClient } from "../admin-client";
import { useAlerts } from "@keycloak/keycloak-ui-shared";
import { ListEmptyState } from "@keycloak/keycloak-ui-shared";
import { KeycloakDataTable } from "@keycloak/keycloak-ui-shared";
import { useRealm } from "../context/realm-context/RealmContext";
import { MemberModal } from "../groups/MembersModal";
import { toUser } from "../user/routes/User";
import { useParams } from "../utils/useParams";
import useToggle from "../utils/useToggle";
import { InviteMemberModal } from "./InviteMemberModal";
import { EditOrganizationParams } from "./routes/EditOrganization";
import { CheckboxFilterComponent } from "../components/dynamic/CheckboxFilterComponent";
import { SearchInputComponent } from "../components/dynamic/SearchInputComponent";
import { translationFormatter } from "../utils/translationFormatter";
import { Modal, ModalVariant } from "@patternfly/react-core"; // Added for Modal
import OrganizationMemberRoleAssignments from "./OrganizationMemberRoleAssignments"; // Added

type MembershipTypeRepresentation = UserRepresentation & {
  membershipType?: string;
};

// UserDetailLink will be kept for now, but direct click action might change for role management
const UserDetailLink = (user: UserRepresentation, viewUserRoles: (user: UserRepresentation) => void) => {
  const { realm } = useRealm();
  // This link navigates to the global user page.
  // We might want to change the primary row click action or add a specific "Manage Roles" action.
  return (
    <>
      <Link to={toUser({ realm, id: user.id!, tab: "settings" })}>
        {user.username}
      </Link>
      {/* Example of adding a manage roles button per row, though actions column is better */}
      {/* <Button variant="link" onClick={() => viewUserRoles(user)}>Manage Org Roles</Button> */}
    </>
  );
};


export const Members = () => {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const { id: orgId } = useParams<EditOrganizationParams>();
  const { addAlert, addError } = useAlerts();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const [open, toggle] = useToggle();
  const [openAddMembers, toggleAddMembers] = useToggle();
  const [openInviteMembers, toggleInviteMembers] = useToggle();
  const [selectedMembers, setSelectedMembers] = useState<UserRepresentation[]>(
    [],
  );
  const [searchText, setSearchText] = useState<string>("");
  const [searchTriggerText, setSearchTriggerText] = useState<string>("");
  const [filteredMembershipTypes, setFilteredMembershipTypes] = useState<
    string[]
  >([]);
  const [isOpen, setIsOpen] = useState(false);
  const [showUserRolesModal, setShowUserRolesModal] = useState(false);
  const [currentUserForRoles, setCurrentUserForRoles] = useState<UserRepresentation | undefined>();

  const membershipOptions = [
    { value: "Managed", label: "Managed" },
    { value: "Unmanaged", label: "Unmanaged" },
  ];

  const onToggleClick = () => {
    setIsOpen(!isOpen);
  };

  const onSelect = (_event: any, value: string) => {
    if (filteredMembershipTypes.includes(value)) {
      setFilteredMembershipTypes(
        filteredMembershipTypes.filter((item) => item !== value),
      );
    } else {
      setFilteredMembershipTypes([...filteredMembershipTypes, value]);
    }
    setIsOpen(false);
    refresh();
  };

  const loader = async (first?: number, max?: number) => {
    try {
      const membershipType =
        filteredMembershipTypes.length === 1
          ? filteredMembershipTypes[0]
          : undefined;

      const memberships: MembershipTypeRepresentation[] =
        await adminClient.organizations.listMembers({
          orgId,
          first,
          max,
          search: searchTriggerText,
          membershipType,
        });

      return memberships;
    } catch (error) {
      addError("organizationsMembersListError", error);
      return [];
    }
  };

  const handleChange = (value: string) => {
    setSearchText(value);
  };

  const handleSearch = () => {
    setSearchTriggerText(searchText);
    refresh();
  };

  const clearInput = () => {
    setSearchText("");
    setSearchTriggerText("");
    refresh();
  };

  const removeMember = async (selectedMembers: UserRepresentation[]) => {
    try {
      await Promise.all(
        selectedMembers.map((user) =>
          adminClient.organizations.delMember({
            orgId,
            userId: user.id!,
          }),
        ),
      );
      addAlert(t("organizationUsersLeft", { count: selectedMembers.length }));
    } catch (error) {
      addError("organizationUsersLeftError", error);
    }

    refresh();
  };

  return (
    <>
      {openAddMembers && (
        <MemberModal
          membersQuery={() => adminClient.organizations.listMembers({ orgId })}
          onAdd={async (selectedRows) => {
            try {
              await Promise.all(
                selectedRows.map((user) =>
                  adminClient.organizations.addMember({
                    orgId,
                    userId: user.id!,
                  }),
                ),
              );
              addAlert(
                t("organizationUsersAdded", { count: selectedRows.length }),
              );
            } catch (error) {
              addError("organizationUsersAddedError", error);
            }
          }}
          onClose={() => {
            toggleAddMembers();
            refresh();
          }}
        />
      )}
      {openInviteMembers && (
        <InviteMemberModal orgId={orgId} onClose={toggleInviteMembers} />
      )}
      <KeycloakDataTable
        key={key}
        loader={loader}
        isPaginated
        ariaLabelKey="membersList"
        onSelect={(members) => setSelectedMembers([...members])}
        canSelectAll
        toolbarItem={
          <>
            <ToolbarItem>
              <SearchInputComponent
                value={searchText}
                onChange={handleChange}
                onSearch={handleSearch}
                onClear={clearInput}
                placeholder={t("searchMembers")}
                aria-label={t("searchMembers")}
              />
            </ToolbarItem>
            <ToolbarItem>
              <Dropdown
                onOpenChange={toggle}
                toggle={(ref) => (
                  <MenuToggle
                    ref={ref}
                    onClick={toggle}
                    isExpanded={open}
                    variant="primary"
                  >
                    {t("addMember")}
                  </MenuToggle>
                )}
                isOpen={open}
              >
                <DropdownList>
                  <DropdownItem
                    onClick={() => {
                      toggleAddMembers();
                      toggle();
                    }}
                  >
                    {t("addRealmUser")}
                  </DropdownItem>
                  <DropdownItem
                    onClick={() => {
                      toggleInviteMembers();
                      toggle();
                    }}
                  >
                    {t("inviteMember")}
                  </DropdownItem>
                </DropdownList>
              </Dropdown>
            </ToolbarItem>
            <ToolbarItem>
              <Button
                variant="plain"
                isDisabled={selectedMembers.length === 0}
                onClick={() => removeMember(selectedMembers)}
              >
                {t("removeMember")}
              </Button>
            </ToolbarItem>
            <ToolbarItem>
              <CheckboxFilterComponent
                filterPlaceholderText={t("filterByMembershipType")}
                isOpen={isOpen}
                options={membershipOptions}
                onOpenChange={(nextOpen) => setIsOpen(nextOpen)}
                onToggleClick={onToggleClick}
                onSelect={onSelect}
                selectedItems={filteredMembershipTypes}
                width={"260px"}
              />
            </ToolbarItem>
          </>
        }
        actions={[
          {
            title: t("remove"),
            onRowClick: async (member) => {
              await removeMember([member]);
            },
          },
          {
            title: t("organizations:manageMemberRoles"), // New action
            onRowClick: (member) => {
              setCurrentUserForRoles(member as UserRepresentation);
              setShowUserRolesModal(true);
            },
          },
        ]}
        columns={[
          {
            name: "username",
            // Pass the handler to UserDetailLink, or handle click on row/action item
            cellRenderer: (row) => UserDetailLink(row as UserRepresentation, (user) => {
              setCurrentUserForRoles(user);
              setShowUserRolesModal(true);
            }),
          },
          {
            name: "email",
          },
          {
            name: "firstName",
          },
          {
            name: "lastName",
          },
          {
            name: "membershipType",
            cellFormatters: [translationFormatter(t)],
          },
        ]}
        emptyState={
          <ListEmptyState
            message={t("emptyMembers")}
            instructions={t("emptyMembersInstructions")}
            secondaryActions={[
              {
                text: t("addRealmUser"),
                onClick: toggleAddMembers,
              },
              {
                text: t("inviteMember"),
                onClick: toggleInviteMembers,
              },
            ]}
          />
        }
        isSearching={filteredMembershipTypes.length > 0}
      />
      {showUserRolesModal && currentUserForRoles && (
        <Modal
          variant={ModalVariant.large}
          title={t("organizations:manageRolesFor", { username: currentUserForRoles.username })}
          isOpen={showUserRolesModal}
          onClose={() => setShowUserRolesModal(false)}
          // Actions for modal can be added here if needed, e.g., a close button
          // For now, relying on the 'x' or escape key.
        >
          <OrganizationMemberRoleAssignments userId={currentUserForRoles.id!} />
        </Modal>
      )}
    </>
  );
};
