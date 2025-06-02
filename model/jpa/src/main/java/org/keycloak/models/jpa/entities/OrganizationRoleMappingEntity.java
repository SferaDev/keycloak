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

package org.keycloak.models.jpa.entities;

import java.io.Serializable;
import java.util.Objects;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Entity
@Table(name = "ORGANIZATION_ROLE_MAPPING")
@IdClass(OrganizationRoleMappingEntity.Key.class)
@NamedQueries({
    @NamedQuery(name = "usersInOrganizationRole", query = "select m.user from OrganizationRoleMappingEntity m where m.roleId = :roleId"),
    @NamedQuery(name =="userHasOrganizationRole", query = "select count(m) from OrganizationRoleMappingEntity m where m.userId = :userId and m.roleId = :roleId"),
    @NamedQuery(name = "organizationRoleMappingsForUser", query = "select m from OrganizationRoleMappingEntity m where m.userId = :userId"), // Renamed for clarity
    // For deleteOrganizationRoleMappingsByRealm, we need to ensure the role is an organization role.
    // Assuming RoleEntity.organizationId is not null for organization roles.
    @NamedQuery(name = "deleteOrganizationRoleMappingsByRealm", query = "delete from OrganizationRoleMappingEntity m where m.roleId IN (select r.id from RoleEntity r where r.realmId = :realmId and r.organizationId IS NOT NULL)"),
    @NamedQuery(name = "deleteOrganizationRoleMappingsByRole", query = "delete from OrganizationRoleMappingEntity m where m.roleId = :roleId"),
    @NamedQuery(name = "deleteOrganizationRoleMappingsByUser", query = "delete from OrganizationRoleMappingEntity m where m.userId = :userId"),
    @NamedQuery(name = "deleteOrganizationRoleMappingByUserAndRole", query = "delete from OrganizationRoleMappingEntity m where m.userId = :userId and m.roleId = :roleId") // Added
})
public class OrganizationRoleMappingEntity {

    @Id
    private String userId;

    @Id
    private String roleId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID", insertable = false, updatable = false)
    private UserEntity user;

    public OrganizationRoleMappingEntity() {
    }

    public OrganizationRoleMappingEntity(String userId, String roleId) {
        this.userId = userId;
        this.roleId = roleId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public static class Key implements Serializable {

        private String userId;
        private String roleId;

        public Key() {
        }

        public Key(String userId, String roleId) {
            this.userId = userId;
            this.roleId = roleId;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getRoleId() {
            return roleId;
        }

        public void setRoleId(String roleId) {
            this.roleId = roleId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Key key = (Key) o;
            return Objects.equals(userId, key.userId) &&
                   Objects.equals(roleId, key.roleId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(userId, roleId);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OrganizationRoleMappingEntity that = (OrganizationRoleMappingEntity) o;
        return Objects.equals(userId, that.userId) &&
               Objects.equals(roleId, that.roleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, roleId);
    }
}
