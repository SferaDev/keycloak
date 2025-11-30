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

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import java.io.Serializable;

/**
 * @author Organization Roles Implementation
 * @version $Revision: 1 $
 */
@NamedQueries({
        @NamedQuery(name="userHasOrganizationRole", query="select m from OrganizationRoleMappingEntity m where m.user = :user and m.organizationRoleId = :organizationRoleId"),
        @NamedQuery(name="userOrganizationRoleMappings", query="select m from OrganizationRoleMappingEntity m where m.user = :user"),
        @NamedQuery(name="userOrganizationRoleMappingIds", query="select m.organizationRoleId from OrganizationRoleMappingEntity m where m.user = :user"),
        @NamedQuery(name="userOrganizationRoleMappingsByOrganization", query="select m from OrganizationRoleMappingEntity m, OrganizationRoleEntity r where m.organizationRoleId = r.id and r.organization.id = :organizationId and m.user = :user"),
        @NamedQuery(name="deleteUserOrganizationRoleMappingsByRealm", query="delete from OrganizationRoleMappingEntity mapping where mapping.user IN (select u from UserEntity u where u.realmId=:realmId)"),
        @NamedQuery(name="deleteUserOrganizationRoleMappingsByOrganizationRole", query="delete from OrganizationRoleMappingEntity m where m.organizationRoleId = :organizationRoleId"),
        @NamedQuery(name="deleteUserOrganizationRoleMappingsByUser", query="delete from OrganizationRoleMappingEntity m where m.user = :user"),
        @NamedQuery(name="deleteUserOrganizationRoleMappingsByOrganization", query="delete from OrganizationRoleMappingEntity m where m.organizationRoleId IN (select r.id from OrganizationRoleEntity r where r.organization.id = :organizationId)")
})
@Table(name="ORG_ROLE_MAPPING")
@Entity
@IdClass(OrganizationRoleMappingEntity.Key.class)
public class OrganizationRoleMappingEntity {

    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    protected UserEntity user;

    @Id
    @Column(name = "ORG_ROLE_ID")
    protected String organizationRoleId;

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public String getOrganizationRoleId() {
        return organizationRoleId;
    }

    public void setOrganizationRoleId(String organizationRoleId) {
        this.organizationRoleId = organizationRoleId;
    }

    public static class Key implements Serializable {

        protected UserEntity user;

        protected String organizationRoleId;

        public Key() {
        }

        public Key(UserEntity user, String organizationRoleId) {
            this.user = user;
            this.organizationRoleId = organizationRoleId;
        }

        public UserEntity getUser() {
            return user;
        }

        public String getOrganizationRoleId() {
            return organizationRoleId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (!organizationRoleId.equals(key.organizationRoleId)) return false;
            if (!user.equals(key.user)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = user.hashCode();
            result = 31 * result + organizationRoleId.hashCode();
            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof OrganizationRoleMappingEntity)) return false;

        OrganizationRoleMappingEntity key = (OrganizationRoleMappingEntity) o;

        if (!organizationRoleId.equals(key.organizationRoleId)) return false;
        if (!user.equals(key.user)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = user.hashCode();
        result = 31 * result + organizationRoleId.hashCode();
        return result;
    }

}