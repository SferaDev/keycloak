/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.organization.admin.resource;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.OrganizationRoleMappingEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

import jakarta.persistence.EntityManager; // For direct EM operations
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class OrganizationMemberRolesResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final OrganizationModel organization;
    private final UserModel user;
    private final AdminEventBuilder adminEvent;
    private final AdminPermissionEvaluator auth;
    private final EntityManager em;

    public OrganizationMemberRolesResource(KeycloakSession session, RealmModel realm, OrganizationModel organization, UserModel user, AdminEventBuilder adminEvent, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.organization = organization;
        this.user = user;
        this.adminEvent = adminEvent.resource(ResourceType.ORGANIZATION_MEMBER_ROLE_MAPPING); // Or a more specific type
        this.auth = auth;
        // Assuming JpaOrganizationProvider exists and provides EntityManager
        // For now, let's get it from a generic JpaDao. If this isn't clean, it can be refactored.
        // This is a common way to get EM in Keycloak services.
        this.em = session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class, "default").getEntityManager();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "List organization roles assigned to the user within this organization.")
    public Stream<RoleRepresentation> listMemberOrganizationRoles() {
        // Permission check (example, adapt as needed):
        // auth.users().requireView(user);
        // auth.organizations().requireViewMember(organization, user); // or similar specific permission

        // Get all roles for the current organization
        List<RoleModel> organizationRoles = organization.getRolesStream().collect(Collectors.toList());

        return organizationRoles.stream()
            .filter(role -> {
                // For each organization role, check if the user has this role mapping
                TypedQuery<Long> query = em.createNamedQuery("userHasOrganizationRole", Long.class);
                query.setParameter("userId", user.getId());
                query.setParameter("roleId", role.getId());
                return query.getSingleResult() > 0;
            .filter(role -> {
                // For each organization role, check if the user has this role mapping
                TypedQuery<Long> query = em.createNamedQuery("userHasOrganizationRole", Long.class);
                query.setParameter("userId", user.getId());
                query.setParameter("roleId", role.getId());
                return query.getSingleResult() > 0;
            })
            .map(ModelToRepresentation::toBriefRepresentation);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Assign organization roles to the user within this organization.")
    public Response addMemberOrganizationRoles(List<RoleRepresentation> roles) {
        // auth.organizations().requireManageMemberRoles(organization, user); // Specific permission

        for (RoleRepresentation roleRep : roles) {
            RoleModel role = realm.getRoleById(roleRep.getId());
            if (role == null) {
                throw ErrorResponse.error("Role not found: " + roleRep.getId(), Response.Status.NOT_FOUND);
            }
            // Verify role is an organization role and belongs to this organization
            if (role.isClientRole() || !Objects.equals(organization.getId(), role.getContainerId())) {
                 // Again, role.getContainerId() for org roles needs to be clear.
                 // Checking entity's organizationId is safer.
                boolean isOrgRoleOfThisOrg = false;
                if (role instanceof org.keycloak.models.jpa.RoleAdapter) {
                    RoleEntity roleEntity = ((org.keycloak.models.jpa.RoleAdapter) role).getEntity();
                    if (Objects.equals(roleEntity.getOrganizationId(), organization.getId())) {
                        isOrgRoleOfThisOrg = true;
                    }
                }
                if (!isOrgRoleOfThisOrg) {
                    throw ErrorResponse.error("Role " + role.getName() + " is not part of organization " + organization.getName(), Response.Status.BAD_REQUEST);
                }
            }

            // Check if mapping already exists
            TypedQuery<Long> query = em.createNamedQuery("userHasOrganizationRole", Long.class);
            query.setParameter("userId", user.getId());
            query.setParameter("roleId", role.getId());
            boolean mappingExists = query.getSingleResult() > 0;

            if (!mappingExists) {
                OrganizationRoleMappingEntity mapping = new OrganizationRoleMappingEntity(user.getId(), role.getId());
                em.persist(mapping);
                adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri())
                    .representation(roleRep).success(); // Event details might need role name, user id, org id
            }
        }
        return Response.noContent().build();
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Unassign organization roles from the user within this organization.")
    public Response removeMemberOrganizationRoles(List<RoleRepresentation> roles) {
        // auth.organizations().requireManageMemberRoles(organization, user); // Specific permission

        for (RoleRepresentation roleRep : roles) {
            RoleModel role = realm.getRoleById(roleRep.getId());
            if (role == null) {
                // Optionally, be lenient and just log, or throw error
                continue;
            }
            // No need to check if it's an org role of this org; if the mapping exists, we remove it.
            // The mapping itself implies it was a valid org role for this user.

            em.createNamedQuery("deleteOrganizationRoleMappingsByUserAndRole") // Assuming this named query exists or will be added
                .setParameter("userId", user.getId())
                .setParameter("roleId", role.getId())
                .executeUpdate();

            adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri())
                .representation(roleRep).success(); // Event details
        }
        return Response.noContent().build();
    }
}
