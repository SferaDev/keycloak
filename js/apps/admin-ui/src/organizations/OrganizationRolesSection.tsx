import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  AlertVariant,
  Button,
  ButtonVariant,
  PageSection,
  ToolbarItem,
} from "@patternfly/react-core";
import { PlusCircleIcon } from "@patternfly/react-icons";

import type RoleRepresentation from "@keycloak/keycloak-admin-client/lib/defs/roleRepresentation";
import { useAdminClient } from "../admin-client";
import { useAlerts } from "@keycloak/keycloak-ui-shared";
import { useConfirmDialog } from "../components/confirm-dialog/ConfirmDialog";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import { useFetch } from "@keycloak/keycloak-ui-shared";
import { useParams } from "../utils/useParams";
import { EditOrganizationParams } from "./routes/EditOrganization";
// TODO: Define toCreateOrganizationRole and toEditOrganizationRole navigation helpers if needed
// import { toCreateOrganizationRole, toEditOrganizationRole } from "./routes";

export default function OrganizationRolesSection() {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const navigate = useNavigate();
  const { realm, id: orgId } = useParams<EditOrganizationParams>(); // id is orgId

  const [roles, setRoles] = useState<RoleRepresentation[]>([]);
  const [selectedRole, setSelectedRole] = useState<RoleRepresentation>();

  useFetch(
    async () => {
      // TODO: Replace with actual adminClient call once available/defined
      // Example: return adminClient.organizations.listRoles({ id: orgId });
      // For now, mocking the API call structure.
      // This will call GET /admin/realms/{realm}/organizations/{orgId}/roles
      const orgRoles = await adminClient.organizations.listRoles({id: orgId});
      return orgRoles || [];
    },
    (fetchedRoles) => setRoles(fetchedRoles),
    [orgId] // Refetch when orgId changes
  );

  const RoleDetailLink = (role: RoleRepresentation) => (
    <Link
      to={/* TODO: toEditOrganizationRole({ realm, orgId, roleId: role.id! }) */ "#"}
    >
      {role.name}
    </Link>
  );

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: "roles:roleDeleteConfirmTitle",
    messageKey: t("roles:roleDeleteConfirm", {
      count: 1,
      name: selectedRole?.name ?? "",
    }),
    continueButtonLabel: "delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        // TODO: Replace with actual adminClient call
        // await adminClient.organizations.delRole({
        //   id: orgId,
        //   roleName: selectedRole!.name!
        // });
        addAlert(t("roles:roleDeletedSuccess"), AlertVariant.success);
        // Refresh list
        adminClient.organizations.listRoles({id: orgId}).then(setRoles);
      } catch (error) {
        addError("roles:roleDeleteError", error);
      }
    },
  });

  return (
    <>
      <DeleteConfirm />
      <PageSection variant="light" className="pf-v5-u-p-0">
        <KeycloakDataTable
          loader={roles} // Directly pass roles fetched by useFetch
          ariaLabelKey="roles:title"
          searchPlaceholderKey="roles:search"
          toolbarItem={
            <ToolbarItem>
              <Button
                data-testid="add-role-button"
                onClick={() => {
                  // TODO: navigate(toCreateOrganizationRole({ realm, orgId }));
                  alert("Navigate to Add Organization Role page (TODO)");
                }}
                icon={<PlusCircleIcon />}
              >
                {t("roles:createRole")}
              </Button>
            </ToolbarItem>
          }
          actions={[
            {
              title: t("edit"),
              onRowClick: (role) => {
                // TODO: navigate(toEditOrganizationRole({ realm, orgId, roleId: role.id! }));
                alert(`Edit role ${role.name} (TODO)`);
              },
            },
            {
              title: t("delete"),
              onRowClick: (role) => {
                setSelectedRole(role);
                toggleDeleteDialog();
              },
            },
          ]}
          columns={[
            {
              name: "name",
              displayKey: "roles:roleName",
              cellRenderer: RoleDetailLink,
            },
            {
              name: "description",
              displayKey: "common:description",
            },
          ]}
        />
      </PageSection>
    </>
  );
}
