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

package org.keycloak.organization.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.OrganizationRoleAttributeEntity;
import org.keycloak.models.jpa.entities.OrganizationRoleEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * @author Organization Roles Implementation
 * @version $Revision: 1 $
 */
public class OrganizationRoleAdapter implements RoleModel {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final OrganizationModel organization;
    private final OrganizationRoleEntity entity;

    public OrganizationRoleAdapter(KeycloakSession session, RealmModel realm, OrganizationModel organization, OrganizationRoleEntity entity) {
        this.session = session;
        this.realm = realm;
        this.organization = organization;
        this.entity = entity;
    }

    @Override
    public String getName() {
        return entity.getName();
    }

    @Override
    public String getDescription() {
        return entity.getDescription();
    }

    @Override
    public void setDescription(String description) {
        entity.setDescription(description);
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public void setName(String name) {
        entity.setName(name);
    }

    @Override
    public boolean isComposite() {
        return !entity.getCompositeRoles().isEmpty();
    }

    @Override
    public void addCompositeRole(RoleModel role) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        entity.getCompositeRoles().add(roleEntity);
    }

    @Override
    public void removeCompositeRole(RoleModel role) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        entity.getCompositeRoles().remove(roleEntity);
    }

    @Override
    public Stream<RoleModel> getCompositesStream(String search, Integer first, Integer max) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String queryText = "select r from RoleEntity r where r.id in :roleIds";
        
        if (search != null && !search.trim().isEmpty()) {
            queryText += " and (lower(r.name) like lower(:search) or lower(r.description) like lower(:search))";
        }
        queryText += " order by r.name";
        
        TypedQuery<RoleEntity> query = em.createQuery(queryText, RoleEntity.class);
        query.setParameter("roleIds", entity.getCompositeRoles().stream().map(RoleEntity::getId).toList());
        
        if (search != null && !search.trim().isEmpty()) {
            query.setParameter("search", "%" + search + "%");
        }
        if (first != null && first >= 0) {
            query.setFirstResult(first);
        }
        if (max != null && max >= 0) {
            query.setMaxResults(max);
        }

        return query.getResultStream().map(roleEntity -> 
            session.roles().getRoleById(realm, roleEntity.getId()));
    }

    @Override
    public boolean isClientRole() {
        return false; // Organization roles are not client roles
    }

    @Override
    public String getContainerId() {
        return organization.getId();
    }

    @Override
    public RoleContainerModel getContainer() {
        return (RoleContainerModel) organization;
    }

    @Override
    public boolean hasRole(RoleModel role) {
        if (this.equals(role)) return true;
        if (!isComposite()) return false;
        return getCompositesStream().anyMatch(compositeRole -> compositeRole.hasRole(role));
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        setAttribute(name, List.of(value));
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        
        // Remove existing attributes with this name
        em.createNamedQuery("deleteOrganizationRoleAttributesByNameAndOrganizationRole")
          .setParameter("organizationRole", entity)
          .setParameter("name", name)
          .executeUpdate();

        // Add new attributes
        if (values != null && !values.isEmpty()) {
            for (String value : values) {
                OrganizationRoleAttributeEntity attr = new OrganizationRoleAttributeEntity();
                attr.setOrganizationRole(entity);
                attr.setName(name);
                attr.setValue(value);
                em.persist(attr);
            }
        }
    }

    @Override
    public void removeAttribute(String name) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        em.createNamedQuery("deleteOrganizationRoleAttributesByNameAndOrganizationRole")
          .setParameter("organizationRole", entity)
          .setParameter("name", name)
          .executeUpdate();
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        return entity.getAttributes().stream()
            .filter(attr -> name.equals(attr.getName()))
            .map(OrganizationRoleAttributeEntity::getValue);
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return entity.getAttributes().stream()
            .collect(
                java.util.stream.Collectors.groupingBy(
                    OrganizationRoleAttributeEntity::getName,
                    java.util.stream.Collectors.mapping(
                        OrganizationRoleAttributeEntity::getValue,
                        java.util.stream.Collectors.toList()
                    )
                )
            );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RoleModel)) return false;
        return getId().equals(((RoleModel) o).getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    public OrganizationRoleEntity getEntity() {
        return entity;
    }
}