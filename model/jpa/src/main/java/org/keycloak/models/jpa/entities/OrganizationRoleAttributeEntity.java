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

import org.hibernate.annotations.Nationalized;

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
    @NamedQuery(name="deleteOrganizationRoleAttributesByNameAndUser", query="delete from  OrganizationRoleAttributeEntity attr where attr.organizationRole IN (select r from OrganizationRoleEntity r where r.organization.id = :organizationId) and attr.name = :name"),
    @NamedQuery(name="deleteOrganizationRoleAttributesByRealm", query="delete from  OrganizationRoleAttributeEntity attr where attr.organizationRole IN (select r from OrganizationRoleEntity r where r.organization.realmId = :realmId)"),
    @NamedQuery(name="deleteOrganizationRoleAttributesByRealmAndLink", query="delete from  OrganizationRoleAttributeEntity attr where attr.organizationRole IN (select r from OrganizationRoleEntity r where r.organization.realmId = :realmId)"),
    @NamedQuery(name="deleteOrganizationRoleAttributes", query="delete from  OrganizationRoleAttributeEntity attr where attr.organizationRole = :organizationRole"),
    @NamedQuery(name="deleteOrganizationRoleAttributesByNameAndOrganizationRole", query="delete from  OrganizationRoleAttributeEntity attr where attr.organizationRole = :organizationRole and attr.name = :name")
})
@Table(name="ORG_ROLE_ATTRIBUTE")
@Entity
@IdClass(OrganizationRoleAttributeEntity.Key.class)
public class OrganizationRoleAttributeEntity {

    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name = "ORG_ROLE_ID")
    protected OrganizationRoleEntity organizationRole;

    @Id
    @Column(name = "NAME")
    protected String name;
    
    @Nationalized
    @Column(name = "VALUE")
    protected String value;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public OrganizationRoleEntity getOrganizationRole() {
        return organizationRole;
    }

    public void setOrganizationRole(OrganizationRoleEntity organizationRole) {
        this.organizationRole = organizationRole;
    }

    public static class Key implements Serializable {

        protected OrganizationRoleEntity organizationRole;

        protected String name;

        public Key() {
        }

        public Key(OrganizationRoleEntity organizationRole, String name) {
            this.organizationRole = organizationRole;
            this.name = name;
        }

        public OrganizationRoleEntity getOrganizationRole() {
            return organizationRole;
        }

        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (name != null ? !name.equals(key.name) : key.name != null) return false;
            if (organizationRole != null ? !organizationRole.equals(key.organizationRole) : key.organizationRole != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = organizationRole != null ? organizationRole.hashCode() : 0;
            result = 31 * result + (name != null ? name.hashCode() : 0);
            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof OrganizationRoleAttributeEntity)) return false;

        OrganizationRoleAttributeEntity key = (OrganizationRoleAttributeEntity) o;

        if (name != null ? !name.equals(key.name) : key.name != null) return false;
        if (organizationRole != null ? !organizationRole.equals(key.organizationRole) : key.organizationRole != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = organizationRole != null ? organizationRole.hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }

}