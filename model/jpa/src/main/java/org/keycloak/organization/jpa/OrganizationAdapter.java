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

import static java.util.Optional.ofNullable;

import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelValidationException;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.RoleModel; // Added
import org.keycloak.models.jpa.JpaModel;
import org.keycloak.models.jpa.RoleAdapter; // Added
import org.keycloak.models.jpa.entities.OrganizationDomainEntity;
import org.keycloak.models.jpa.entities.OrganizationEntity;
import org.keycloak.models.jpa.entities.RoleEntity; // Added
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.organization.OrganizationProvider;
import jakarta.persistence.EntityManager; // Added
import jakarta.persistence.TypedQuery; // Added
import org.keycloak.utils.EmailValidationUtil;
import org.keycloak.utils.StringUtil;

public final class OrganizationAdapter implements OrganizationModel, JpaModel<OrganizationEntity> {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final OrganizationEntity entity;
    private final OrganizationProvider provider;
    private final EntityManager em; // Added
    private GroupModel group;
    private Map<String, List<String>> attributes;

    public OrganizationAdapter(KeycloakSession session, RealmModel realm, OrganizationEntity entity, OrganizationProvider provider) {
        this.session = session;
        this.realm = realm;
        this.entity = entity;
        this.provider = provider;
        this.em = session.getProvider(JpaOrganizationProvider.class).getEntityManager(); // Added
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    RealmModel getRealm() {
        return realm;
    }

    public String getGroupId() {
        return entity.getGroupId();
    }

    void setGroupId(String id) {
        entity.setGroupId(id);
    }

    @Override
    public void setName(String name) {
        entity.setName(name);
    }

    @Override
    public String getName() {
        return entity.getName();
    }

    @Override
    public String getAlias() {
        return entity.getAlias();
    }

    @Override
    public void setAlias(String alias) {
        if (StringUtil.isBlank(alias)) {
            alias = getName();
        }
        if (alias.equals(entity.getAlias())) {
            return;
        }
        if (StringUtil.isNotBlank(entity.getAlias())) {
            throw new ModelValidationException("Cannot change the alias");
        }
        entity.setAlias(alias);
    }

    @Override
    public boolean isEnabled() {
        return provider.isEnabled() && entity.isEnabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        entity.setEnabled(enabled);
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
    public String getRedirectUrl() {
        return entity.getRedirectUrl();
    }

    @Override
    public void setRedirectUrl(String redirectUrl) {
        entity.setRedirectUrl(redirectUrl);
    }

    @Override
    public void setAttributes(Map<String, List<String>> attributes) {
        if (attributes == null) {
            return;
        }

        // add organization to the session as the following code updates the underlying group
        OrganizationModel current = session.getContext().getOrganization();
        if (current == null) {
            session.getContext().setOrganization(this);
        }

        try {
            Set<String> attrsToRemove = getAttributes().keySet();
            attrsToRemove.removeAll(attributes.keySet());
            attrsToRemove.forEach(group::removeAttribute);
            attributes.forEach(group::setAttribute);
        } finally {
            if (current == null) {
                session.getContext().setOrganization(null);
            }
        }
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        if (attributes == null) {
            attributes = ofNullable(getGroup().getAttributes()).orElse(Map.of());
        }
        return attributes;
    }

    @Override
    public Stream<OrganizationDomainModel> getDomains() {
        return entity.getDomains().stream().map(this::toModel);
    }

    @Override
    public void setDomains(Set<OrganizationDomainModel> domains) {
        if (domains == null || domains.isEmpty()) {
            throw new ModelValidationException("You must provide at least one domain");
        }

        Map<String, OrganizationDomainModel> modelMap = domains.stream()
                .map(this::validateDomain)
                .collect(Collectors.toMap(OrganizationDomainModel::getName, Function.identity()));

        for (OrganizationDomainEntity domainEntity : new HashSet<>(this.entity.getDomains())) {
            // update the existing domain (for now, only the verified flag can be changed).
            if (modelMap.containsKey(domainEntity.getName())) {
                domainEntity.setVerified(modelMap.get(domainEntity.getName()).isVerified());
                modelMap.remove(domainEntity.getName());
            } else {
                // remove domain that is not found in the new set.
                this.entity.removeDomain(domainEntity);
                // check if any idp is assigned to the removed domain, and unset the domain if that's the case.
                getIdentityProviders()
                        .filter(idp -> Objects.equals(domainEntity.getName(), idp.getConfig().get(ORGANIZATION_DOMAIN_ATTRIBUTE)))
                        .forEach(idp -> {
                            idp.getConfig().remove(ORGANIZATION_DOMAIN_ATTRIBUTE);
                            session.identityProviders().update(idp);
                        });
            }
        }

        // create the remaining domains.
        for (OrganizationDomainModel model : modelMap.values()) {
            OrganizationDomainEntity domainEntity = new OrganizationDomainEntity();
            domainEntity.setId(KeycloakModelUtils.generateId());
            domainEntity.setName(model.getName());
            domainEntity.setVerified(model.isVerified());
            domainEntity.setOrganization(this.entity);
            this.entity.addDomain(domainEntity);
        }
    }

    @Override
    public Stream<IdentityProviderModel> getIdentityProviders() {
        return provider.getIdentityProviders(this);
    }

    @Override
    public boolean isManaged(UserModel user) {
        return provider.isManagedMember(this, user);
    }

    @Override
    public boolean isMember(UserModel user) {
        return provider.isMember(this, user);
    }

    @Override
    public OrganizationEntity getEntity() {
        return entity;
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("id=")
                .append(getId())
                .append(",")
                .append("name=")
                .append(getName())
                .append(",")
                .append("realm=")
                .append(getRealm().getName())
                .append(",")
                .append("groupId=")
                .append(getGroupId()).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OrganizationModel)) return false;

        OrganizationModel that = (OrganizationModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    private OrganizationDomainModel toModel(OrganizationDomainEntity entity) {
        return new OrganizationDomainModel(entity.getName(), entity.isVerified());
    }

    /**
     * Validates the domain. Specifically, the method first checks if the specified domain is valid,
     * and then checks if the domain is not already linked to a different organization.
     *
     * @param domainModel the {@link OrganizationDomainModel} representing the domain being added.
     * @throws {@link ModelValidationException} if the domain is invalid or is already linked to a different organization.
     */
    private OrganizationDomainModel validateDomain(OrganizationDomainModel domainModel) {
        String domainName = domainModel.getName();

        // we rely on the same validation util used by the EmailValidator to ensure the domain part is consistently validated.
        if (StringUtil.isBlank(domainName) || !EmailValidationUtil.isValidEmail("nouser@" + domainName)) {
            throw new ModelValidationException("The specified domain is invalid: " + domainName);
        }
        OrganizationModel orgModel = provider.getByDomainName(domainName);
        if (orgModel != null && !Objects.equals(getId(), orgModel.getId())) {
            throw new ModelValidationException("Domain " + domainName + " is already linked to another organization in realm " + realm.getName());
        }
        return domainModel;
    }

    private GroupModel getGroup() {
        if (group == null) {
            group = realm.getGroupById(getGroupId());
        }
        return group;
    }

    // Implementation of RoleContainerModel methods

    @Override
    public RoleModel addRole(String name) {
        return this.addRole(null, name);
    }

    @Override
    public RoleModel addRole(String id, String name) {
        if (id != null && em.find(RoleEntity.class, id) != null) {
            throw new ModelDuplicateException("Role with id '" + id + "' already exists");
        }
        if (name != null && getRole(name) != null) {
            throw new ModelDuplicateException("Role with name '" + name + "' already exists in organization " + getName());
        }

        RoleEntity roleEntity = new RoleEntity();
        roleEntity.setId(id == null ? KeycloakModelUtils.generateId() : id);
        roleEntity.setName(name);
        roleEntity.setRealmId(realm.getId());
        roleEntity.setOrganizationId(this.getId());
        roleEntity.setClientRole(false);
        // For non-client roles, clientRealmConstraint is typically the realmId.
        // This is important for the unique constraint on RoleEntity.
        roleEntity.setClientRealmConstraint(realm.getId());
        em.persist(roleEntity);
        session.getKeycloakSessionFactory().publish(new RoleModel.RoleCreatedEvent() {
            @Override
            public RoleModel getRole() {
                return new RoleAdapter(session, realm, em, roleEntity);
            }

            @Override
            public KeycloakSession getKeycloakSession() {
                return session;
            }
        });
        return new RoleAdapter(session, realm, em, roleEntity);
    }

    @Override
    public RoleModel getRole(String name) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("getOrganizationRoleByName", RoleEntity.class);
        query.setParameter("realmId", realm.getId());
        query.setParameter("organizationId", this.getId());
        query.setParameter("name", name);
        List<RoleEntity> results = query.getResultList();
        if (results.isEmpty()) return null;
        return new RoleAdapter(session, realm, em, results.get(0));
    }

    @Override
    public Stream<RoleModel> getRolesStream() {
        return getRolesStream(null, null);
    }

    @Override
    public Stream<RoleModel> getRolesStream(Integer firstResult, Integer maxResults) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("getOrganizationRoles", RoleEntity.class);
        query.setParameter("realmId", realm.getId());
        query.setParameter("organizationId", this.getId());
        if (firstResult != null && firstResult >= 0) {
            query.setFirstResult(firstResult);
        }
        if (maxResults != null && maxResults >= 0) {
            query.setMaxResults(maxResults);
        }
        return query.getResultStream().map(entity -> new RoleAdapter(session, realm, em, entity));
    }

    @Override
    public Stream<RoleModel> searchForRolesStream(String search, Integer firstResult, Integer maxResults) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("searchForOrganizationRoles", RoleEntity.class);
        query.setParameter("realmId", realm.getId());
        query.setParameter("organizationId", this.getId());
        query.setParameter("search", "%" + search.toLowerCase() + "%");
        if (firstResult != null && firstResult >= 0) {
            query.setFirstResult(firstResult);
        }
        if (maxResults != null && maxResults >= 0) {
            query.setMaxResults(maxResults);
        }
        return query.getResultStream().map(entity -> new RoleAdapter(session, realm, em, entity));
    }

    @Override
    public boolean removeRole(RoleModel role) {
        if (role == null || !Objects.equals(role.getContainerId(), realm.getId()) || role.isClientRole()) {
             // Basic check: Role must be a realm role (implicitly, org roles are realm-scoped)
             // and its organizationId must match this organization.
             // RoleAdapter.getContainerId() for a non-client role returns realmId.
             // We also need to check role.getEntity().getOrganizationId().equals(this.getId())
             // This is better handled by session.roles().removeRole if it can verify ownership.
             // For now, let's assume session.roles().removeRole does the right checks or we enhance it later.
            RoleEntity roleEntity = null;
            if (role instanceof RoleAdapter) {
                roleEntity = ((RoleAdapter) role).getEntity();
            } else {
                // Fallback if not a RoleAdapter, though it usually is.
                RoleAdapter adapter = (RoleAdapter) session.roles().getRoleById(realm, role.getId());
                if (adapter != null) roleEntity = adapter.getEntity();
            }

            if (roleEntity == null || !Objects.equals(roleEntity.getOrganizationId(), this.getId())) {
                return false; // Not an org role of this organization
            }
        }
        // Delegate to RoleProvider for proper removal, including composite role handling.
        return session.roles().removeRole(role);
    }
}
