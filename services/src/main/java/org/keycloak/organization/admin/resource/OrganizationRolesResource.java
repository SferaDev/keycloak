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
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;

import java.util.List;
import java.util.stream.Stream;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class OrganizationRolesResource {

    private final KeycloakSession session;
    private final OrganizationProvider provider;
    private final OrganizationModel organization;
    private final AdminEventBuilder adminEvent;

    public OrganizationRolesResource(KeycloakSession session, OrganizationModel organization, AdminEventBuilder adminEvent) {
        this.session = session;
        this.provider = session.getProvider(OrganizationProvider.class);
        this.organization = organization;
        this.adminEvent = adminEvent.resource(ResourceType.ORGANIZATION_ROLE);
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Get all organization roles")
    @APIResponses(value = {
        @APIResponse(responseCode = "200", description = "List of organization roles", content = @Content(schema = @Schema(implementation = RoleRepresentation.class)))
    })
    public List<RoleRepresentation> getRoles(
            @Parameter(description = "Search term") @QueryParam("search") String search,
            @Parameter(description = "First result") @QueryParam("first") Integer first,
            @Parameter(description = "Maximum results") @QueryParam("max") Integer max) {

        Stream<RoleModel> rolesStream;
        if (search != null && !search.trim().isEmpty()) {
            rolesStream = organization.searchForRolesStream(search, first, max);
        } else {
            rolesStream = organization.getRolesStream(first, max);
        }

        return rolesStream.map(ModelToRepresentation::toRepresentation).toList();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Create a new organization role")
    @APIResponses(value = {
        @APIResponse(responseCode = "201", description = "Created"),
        @APIResponse(responseCode = "400", description = "Bad Request"),
        @APIResponse(responseCode = "409", description = "Role name already exists")
    })
    public Response createRole(RoleRepresentation rep) {
        try {
            if (rep.getName() == null || rep.getName().trim().isEmpty()) {
                throw ErrorResponse.error("Role name cannot be empty", Response.Status.BAD_REQUEST);
            }

            if (organization.getRole(rep.getName()) != null) {
                throw ErrorResponse.error("Role name already exists", Response.Status.CONFLICT);
            }

            RoleModel role = organization.addRole(rep.getName());
            if (rep.getDescription() != null) {
                role.setDescription(rep.getDescription());
            }
            if (rep.getAttributes() != null) {
                rep.getAttributes().forEach(role::setAttribute);
            }

            adminEvent.operation(OperationType.CREATE)
                     .resourcePath(session.getContext().getUri(), role.getId())
                     .representation(rep)
                     .success();

            return Response.created(session.getContext().getUri().getAbsolutePathBuilder().path(role.getId()).build())
                          .build();

        } catch (Exception e) {
            return ErrorResponse.error("Failed to create role: " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @Path("{roleName}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Get organization role by name")
    @APIResponses(value = {
        @APIResponse(responseCode = "200", description = "Organization role", content = @Content(schema = @Schema(implementation = RoleRepresentation.class))),
        @APIResponse(responseCode = "404", description = "Role not found")
    })
    public RoleRepresentation getRole(@PathParam("roleName") String roleName) {
        RoleModel role = organization.getRole(roleName);
        if (role == null) {
            throw ErrorResponse.error("Role not found", Response.Status.NOT_FOUND);
        }
        return ModelToRepresentation.toRepresentation(role);
    }

    @Path("{roleName}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Update organization role")
    @APIResponses(value = {
        @APIResponse(responseCode = "204", description = "Updated"),
        @APIResponse(responseCode = "400", description = "Bad Request"),
        @APIResponse(responseCode = "404", description = "Role not found")
    })
    public Response updateRole(@PathParam("roleName") String roleName, RoleRepresentation rep) {
        RoleModel role = organization.getRole(roleName);
        if (role == null) {
            throw ErrorResponse.error("Role not found", Response.Status.NOT_FOUND);
        }

        if (rep.getDescription() != null) {
            role.setDescription(rep.getDescription());
        }
        if (rep.getAttributes() != null) {
            rep.getAttributes().forEach(role::setAttribute);
        }

        adminEvent.operation(OperationType.UPDATE)
                 .resourcePath(session.getContext().getUri())
                 .representation(rep)
                 .success();

        return Response.noContent().build();
    }

    @Path("{roleName}")
    @DELETE
    @Tag(name = KeycloakOpenAPI.Admin.Tags.ORGANIZATIONS)
    @Operation(summary = "Delete organization role")
    @APIResponses(value = {
        @APIResponse(responseCode = "204", description = "Deleted"),
        @APIResponse(responseCode = "404", description = "Role not found")
    })
    public Response deleteRole(@PathParam("roleName") String roleName) {
        RoleModel role = organization.getRole(roleName);
        if (role == null) {
            throw ErrorResponse.error("Role not found", Response.Status.NOT_FOUND);
        }

        boolean removed = organization.removeRole(role);
        if (removed) {
            adminEvent.operation(OperationType.DELETE)
                     .resourcePath(session.getContext().getUri())
                     .success();
            return Response.noContent().build();
        } else {
            throw ErrorResponse.error("Failed to delete role", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}