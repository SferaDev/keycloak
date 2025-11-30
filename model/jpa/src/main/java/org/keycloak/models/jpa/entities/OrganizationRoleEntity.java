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

import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;
import org.hibernate.annotations.Nationalized;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * @author Organization Roles Implementation
 * @version $Revision: 1 $
 */
@Entity
@Table(name="ORG_ROLE", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "NAME", "ORGANIZATION_ID" })
})
@NamedQueries({
        @NamedQuery(name="getOrganizationRoles", query="select role from OrganizationRoleEntity role where role.organization.id = :organizationId order by role.name"),
        @NamedQuery(name="getOrganizationRoleIds", query="select role.id from OrganizationRoleEntity role where role.organization.id = :organizationId"),
        @NamedQuery(name="getOrganizationRoleByName", query="select role from OrganizationRoleEntity role where role.name = :name and role.organization.id = :organizationId"),
        @NamedQuery(name="getOrganizationRoleIdByName", query="select role.id from OrganizationRoleEntity role where role.name = :name and role.organization.id = :organizationId"),
        @NamedQuery(name="searchForOrganizationRoles", query="select role from OrganizationRoleEntity role where role.organization.id = :organizationId and ( lower(role.name) like :search or lower(role.description) like :search ) order by role.name"),
        @NamedQuery(name="getOrganizationRoleIdsFromIdList", query="select role.id from OrganizationRoleEntity role where role.organization.id = :organizationId and role.id in :ids order by role.name ASC"),
        @NamedQuery(name="getOrganizationRoleIdsByNameContainingFromIdList", query="select role.id from OrganizationRoleEntity role where role.organization.id = :organizationId and lower(role.name) like lower(concat('%',:search,'%')) and role.id in :ids order by role.name ASC"),
        @NamedQuery(name="deleteOrganizationRolesByOrganization", query="delete from OrganizationRoleEntity role where role.organization.id = :organizationId")
})
public class OrganizationRoleEntity {
    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;

    @Nationalized
    @Column(name = "NAME")
    private String name;
    
    @Nationalized
    @Column(name = "DESCRIPTION")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ORGANIZATION_ID")
    private OrganizationEntity organization;

    @ManyToMany(fetch = FetchType.LAZY, cascade = {})
    @JoinTable(name = "ORG_ROLE_COMPOSITE", joinColumns = @JoinColumn(name = "COMPOSITE"), inverseJoinColumns = @JoinColumn(name = "CHILD_ROLE"))
    private Set<RoleEntity> compositeRoles;

    @OneToMany(cascade = CascadeType.REMOVE, orphanRemoval = false, mappedBy="organizationRole")
    @Fetch(FetchMode.SELECT)
    @BatchSize(size = 20)
    protected List<OrganizationRoleAttributeEntity> attributes = new LinkedList<>();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public OrganizationEntity getOrganization() {
        return organization;
    }

    public void setOrganization(OrganizationEntity organization) {
        this.organization = organization;
    }

    public Set<RoleEntity> getCompositeRoles() {
        if (compositeRoles == null) {
            compositeRoles = new HashSet<>();
        }
        return compositeRoles;
    }

    public void setCompositeRoles(Set<RoleEntity> compositeRoles) {
        this.compositeRoles = compositeRoles;
    }

    public List<OrganizationRoleAttributeEntity> getAttributes() {
        if (attributes == null) {
            attributes = new LinkedList<>();
        }
        return attributes;
    }

    public void setAttributes(List<OrganizationRoleAttributeEntity> attributes) {
        this.attributes = attributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof OrganizationRoleEntity)) return false;

        OrganizationRoleEntity that = (OrganizationRoleEntity) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}