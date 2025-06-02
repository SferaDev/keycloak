import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router-dom";
import { AlertVariant, PageSection } from "@patternfly/react-core";

import type RoleRepresentation from "@keycloak/keycloak-admin-client/lib/defs/roleRepresentation";
import { useAdminClient } from "../admin-client";
import { useAlerts } from "@keycloak/keycloak-ui-shared";
import { AddRoles } from "../components/role-mapping/AddRoles";
import { EditOrganizationParams } from "./routes/EditOrganization";
import { getEffectiveRoles } from "../components/role-mapping/role-mapping";
// TODO: Need a specific way to list effective roles for a user within an organization context if different from realm/client effective roles.
// For now, this component will manage direct organization role assignments.

type OrganizationMemberRoleAssignmentsProps = {
  userId: string;
  // orgId is available via useParams in this component's context if it's rendered under the org route
};

export default function OrganizationMemberRoleAssignments({ userId }: OrganizationMemberRoleAssignmentsProps) {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const { realm, id: orgId } = useParams<EditOrganizationParams>(); // id is orgId from the route

  const [assignedRoles, setAssignedRoles] = useState<RoleRepresentation[]>([]);
  const [availableOrgRoles, setAvailableOrgRoles] = useState<RoleRepresentation[]>([]);
  const [effectiveRealmRoles, setEffectiveRealmRoles] = useState<RoleRepresentation[]>([]);
  const [effectiveClientRoles, setEffectiveClientRoles] = useState< Map<string, RoleRepresentation[]>>(new Map());
  const [isLoading, setIsLoading] = useState(false);

  const fetchAssignedRoles = async () => {
    setIsLoading(true);
    try {
      // API to get roles for a user within an org
      // GET /realms/{realm}/organizations/{orgId}/members/{userId}/roles
      const roles = await adminClient.organizations.listMemberRoles({ orgId, userId });
      setAssignedRoles(roles || []);
    } catch (error) {
      addError(t("organizations:errorFetchingAssignedRoles"), error);
      setAssignedRoles([]);
    }
    setIsLoading(false);
  };

  const fetchAvailableOrgRoles = async () => {
    try {
      // API to get all roles for an org
      // GET /realms/{realm}/organizations/{orgId}/roles
      const roles = await adminClient.organizations.listRoles({ id: orgId });
      setAvailableOrgRoles(roles || []);
    } catch (error) {
      addError(t("organizations:errorFetchingAvailableOrgRoles"), error);
      setAvailableOrgRoles([]);
    }
  };

  // Fetch effective roles (realm and client) for the user - this might not be strictly necessary
  // if we are only showing/managing this specific org's roles.
  // However, AddRoles component might use it.
  const fetchEffectiveRoles = async () => {
    const effective = await getEffectiveRoles(adminClient, realm, userId);
    setEffectiveRealmRoles(effective.realmRoles);
    setEffectiveClientRoles(effective.clientRoles);
  };


  useEffect(() => {
    fetchAssignedRoles();
    fetchAvailableOrgRoles();
    // fetchEffectiveRoles(); // Decide if this is needed for org context
  }, [orgId, userId]);

  const assignRoles = async (roles: RoleRepresentation[]) => {
    try {
      // API to assign org roles to user
      // POST /realms/{realm}/organizations/{orgId}/members/{userId}/roles
      await adminClient.organizations.addMemberRoles({
        orgId,
        userId,
        roles,
      });
      addAlert(t("roles:roleMappingUpdatedSuccess"), AlertVariant.success);
      fetchAssignedRoles(); // Refresh assigned roles
    } catch (error) {
      addError(t("roles:errorUpdatingRoleMapping"), error);
    }
  };

  const unassignRoles = async (roles: RoleRepresentation[]) => {
    try {
      // API to unassign org roles from user
      // DELETE /realms/{realm}/organizations/{orgId}/members/{userId}/roles
      await adminClient.organizations.delMemberRoles({
        orgId,
        userId,
        roles,
      });
      addAlert(t("roles:roleMappingRemovedSuccess"), AlertVariant.success);
      fetchAssignedRoles(); // Refresh assigned roles
    } catch (error) {
      addError(t("roles:errorUpdatingRoleMapping"), error);
    }
  };

  return (
    <PageSection variant="light">
      <AddRoles
        isRadio // Assuming single role assignment for simplicity, or adapt AddRoles
        onAssign={assignRoles}
        onCancel={() => { /* TODO: Close modal or navigate back if in a dedicated view */ }}
        assignedRoles={assignedRoles.map((role) => role.name!)} // AddRoles expects role names
        availableRoles={availableOrgRoles} // Only show roles from this organization as assignable
        // The AddRoles component might need adjustments if it's too tied to realm/client role concepts.
        // For now, we pass availableOrgRoles. It lists roles and allows selection.
        // It might internally try to fetch realm/client roles if not adapted.
        // We might need a simpler role assignment component or adapt AddRoles.
        // For now, assuming AddRoles can work with a plain list of available roles.

        // The following props are for the full AddRoles component, might not all be relevant
        // or might need context-specific adaptation.
        title={t("organizations:assignOrganizationRoles")}
        // type="organization" // May need to tell AddRoles the context
        // The `resources` prop in AddRoles is for client roles. Not directly applicable here.
        // We are providing a flat list of available organization roles.
      />
      {/* TODO: Display currently assigned organization roles with an option to unassign */}
      {/* This could be a simple table listing assignedRoles with a remove button per role,
          or integrated into AddRoles if it supports showing assigned and unassigning. */}
    </PageSection>
  );
}
