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
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;

import java.util.List;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class OrganizationMemberRoleMappingResource {

    private final KeycloakSession session;
    private final OrganizationProvider provider;
    private final OrganizationModel organization;
    private final UserModel user;
    private final AdminEventBuilder adminEvent;

    public OrganizationMemberRoleMappingResource(KeycloakSession session, OrganizationModel organization, UserModel user, AdminEventBuilder adminEvent) {
        this.session = session;
        this.provider = session.getProvider(OrganizationProvider.class);
        this.organization = organization;
        this.user = user;
        this.adminEvent = adminEvent.resource(ResourceType.ORGANIZATION_ROLE_MAPPING);
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Get organization roles assigned to member")
    @APIResponses(value = {
        @APIResponse(responseCode = "200", description = "List of organization roles", content = @Content(schema = @Schema(implementation = RoleRepresentation.class)))
    })
    public List<RoleRepresentation> getOrganizationRoleMappings() {
        if (!provider.isMember(organization, user)) {
            throw ErrorResponse.error("User is not a member of the organization", Response.Status.BAD_REQUEST);
        }

        return provider.getOrganizationRolesForUser(organization, user)
                      .map(ModelToRepresentation::toRepresentation)
                      .toList();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Add organization roles to member")
    @APIResponses(value = {
        @APIResponse(responseCode = "204", description = "Roles added"),
        @APIResponse(responseCode = "400", description = "Bad Request"),
        @APIResponse(responseCode = "404", description = "Role not found")
    })
    public Response addOrganizationRoleMappings(List<RoleRepresentation> roles) {
        if (!provider.isMember(organization, user)) {
            throw ErrorResponse.error("User is not a member of the organization", Response.Status.BAD_REQUEST);
        }

        for (RoleRepresentation roleRep : roles) {
            RoleModel role = organization.getRole(roleRep.getName());
            if (role == null) {
                throw ErrorResponse.error("Role not found: " + roleRep.getName(), Response.Status.NOT_FOUND);
            }

            boolean added = provider.addOrganizationRoleToUser(organization, user, role);
            if (!added) {
                throw ErrorResponse.error("Failed to add role: " + roleRep.getName(), Response.Status.INTERNAL_SERVER_ERROR);
            }
        }

        adminEvent.operation(OperationType.CREATE)
                 .resourcePath(session.getContext().getUri())
                 .representation(roles)
                 .success();

        return Response.noContent().build();
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Remove organization roles from member")
    @APIResponses(value = {
        @APIResponse(responseCode = "204", description = "Roles removed"),
        @APIResponse(responseCode = "400", description = "Bad Request"),
        @APIResponse(responseCode = "404", description = "Role not found")
    })
    public Response removeOrganizationRoleMappings(List<RoleRepresentation> roles) {
        if (!provider.isMember(organization, user)) {
            throw ErrorResponse.error("User is not a member of the organization", Response.Status.BAD_REQUEST);
        }

        for (RoleRepresentation roleRep : roles) {
            RoleModel role = organization.getRole(roleRep.getName());
            if (role == null) {
                throw ErrorResponse.error("Role not found: " + roleRep.getName(), Response.Status.NOT_FOUND);
            }

            boolean removed = provider.removeOrganizationRoleFromUser(organization, user, role);
            if (!removed) {
                throw ErrorResponse.error("Failed to remove role: " + roleRep.getName(), Response.Status.INTERNAL_SERVER_ERROR);
            }
        }

        adminEvent.operation(OperationType.DELETE)
                 .resourcePath(session.getContext().getUri())
                 .representation(roles)
                 .success();

        return Response.noContent().build();
    }
}