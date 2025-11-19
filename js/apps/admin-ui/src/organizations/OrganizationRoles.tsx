import {
  Button,
  PageSection,
  ToolbarItem,
} from "@patternfly/react-core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useAdminClient } from "../admin-client";
import { useAlerts } from "@keycloak/keycloak-ui-shared";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import { ListEmptyState } from "../components/list-empty-state/ListEmptyState";
import { useRealm } from "../context/realm-context/RealmContext";
import { useParams } from "../utils/useParams";
import type { EditOrganizationParams } from "./routes/EditOrganization";
import type RoleRepresentation from "@keycloak/keycloak-admin-client/lib/defs/roleRepresentation";
import { DeleteConfirm } from "../components/confirm-dialog/DeleteConfirm";

export default function OrganizationRoles() {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const { realm } = useRealm();
  const { id: organizationId } = useParams<EditOrganizationParams>();
  
  const [selectedRole, setSelectedRole] = useState<RoleRepresentation>();

  const loader = async (first?: number, max?: number, search?: string) => {
    const params = {
      first,
      max,
      search,
    };
    
    try {
      const roles = await adminClient.organizations.roles.find(
        { id: organizationId },
        params
      );
      return roles || [];
    } catch (error) {
      return [];
    }
  };

  const handleDelete = async () => {
    if (!selectedRole?.name) return;
    
    try {
      await adminClient.organizations.roles.delByName({
        id: organizationId,
        roleName: selectedRole.name,
      });
      addAlert(t("roleDeletedSuccess"));
      setSelectedRole(undefined);
    } catch (error) {
      addError("roleDeleteError", error);
    }
  };

  const RoleDetailLink = ({ role }: { role: RoleRepresentation }) => (
    <Link to={`/${realm}/organizations/${organizationId}/roles/${role.name}`}>
      {role.name}
    </Link>
  );

  return (
    <>
      <DeleteConfirm
        continueButtonLabel="delete"
        titleKey="deleteRole"
        messageKey="deleteRoleConfirm"
        messageParams={[selectedRole?.name || ""]}
        open={!!selectedRole}
        toggleDialog={() => setSelectedRole(undefined)}
        onConfirm={handleDelete}
      />
      <PageSection variant="light" padding={{ default: "noPadding" }}>
        <KeycloakDataTable
          key={organizationId}
          loader={loader}
          ariaLabelKey="organizationRoles"
          searchPlaceholderKey="searchForRole"
          toolbarItem={
            <ToolbarItem>
              <Button
                data-testid="create-role"
                component={(props) => (
                  <Link
                    {...props}
                    to={`/${realm}/organizations/${organizationId}/roles/new`}
                  />
                )}
              >
                {t("createRole")}
              </Button>
            </ToolbarItem>
          }
          actions={[
            {
              title: t("delete"),
              onRowClick: (role) => setSelectedRole(role),
            },
          ]}
          columns={[
            {
              name: "name",
              displayKey: "name",
              cellRenderer: RoleDetailLink,
            },
            {
              name: "description",
              displayKey: "description",
            },
          ]}
          emptyState={
            <ListEmptyState
              message={t("emptyOrganizationRoles")}
              instructions={t("emptyOrganizationRolesInstructions")}
              primaryActionText={t("createRole")}
              primaryActionLink={`/${realm}/organizations/${organizationId}/roles/new`}
            />
          }
          isPaginated
        />
      </PageSection>
    </>
  );
}