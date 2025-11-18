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

package org.keycloak.organization.protocol.mappers.saml;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.organization.protocol.mappers.oidc.OrganizationScope;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class OrganizationRoleMapper extends AbstractSAMLProtocolMapper implements SAMLAttributeStatementMapper, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "saml-organization-role-mapper";
    private static final String ORGANIZATION_ROLE_CLAIM = "organization_role";
    
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(AttributeStatementHelper.SAML_ATTRIBUTE_NAME);
        property.setLabel("Attribute name");
        property.setDefaultValue(ORGANIZATION_ROLE_CLAIM);
        property.setHelpText("Name of the SAML attribute you want to put organization roles into. You can change this to any value you want.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        
        property = new ProviderConfigProperty();
        property.setName(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT);
        property.setLabel("SAML Attribute NameFormat");
        property.setHelpText("SAML Attribute NameFormat. Can be basic, URI reference, or unspecified.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(List.of(AttributeStatementHelper.BASIC, AttributeStatementHelper.URI_REFERENCE, AttributeStatementHelper.UNSPECIFIED));
        property.setDefaultValue(AttributeStatementHelper.BASIC);
        configProperties.add(property);
        
        property = new ProviderConfigProperty();
        property.setName(AttributeStatementHelper.FRIENDLY_NAME);
        property.setLabel("Friendly Name");
        property.setHelpText("Standard SAML attribute setting. An optional, more human-readable form of the attribute's name that can be provided if the actual attribute name is cryptic.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        
        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.MULTIVALUED);
        property.setLabel(ProtocolMapperUtils.MULTIVALUED_LABEL);
        property.setHelpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue("true");
        configProperties.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Organization Role list";
    }

    @Override
    public String getDisplayCategory() {
        return "Organization Mapper";
    }

    @Override
    public String getHelpText() {
        return "Map organization roles to a SAML attribute.";
    }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        String orgId = clientSession.getNote(OrganizationModel.ORGANIZATION_ATTRIBUTE);
        Stream<OrganizationModel> organizations;

        if (orgId == null) {
            organizations = resolveFromRequestedScopes(session, userSession, clientSession);
        } else {
            OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
            OrganizationModel organization = orgProvider.getById(orgId);
            organizations = organization != null ? Stream.of(organization) : Stream.empty();
        }

        List<String> organizationRoles = new ArrayList<>();
        OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
        
        for (OrganizationModel organization : organizations.toList()) {
            if (organization == null || !organization.isEnabled() || !organization.isMember(userSession.getUser())) {
                continue;
            }

            List<String> roles = orgProvider.getOrganizationRolesForUser(organization, userSession.getUser())
                .map(role -> organization.getAlias() + ":" + role.getName())
                .toList();
            
            organizationRoles.addAll(roles);
        }

        if (!organizationRoles.isEmpty()) {
            AttributeType attributeType = AttributeStatementHelper.createAttributeType(mappingModel);
            
            for (String role : organizationRoles) {
                attributeType.addAttributeValue(role);
            }
            
            attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attributeType));
        }
    }

    private Stream<OrganizationModel> resolveFromRequestedScopes(KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        String rawScopes = clientSession.getNote("scope");
        if (rawScopes == null) {
            return Stream.empty();
        }

        OrganizationScope scope = OrganizationScope.valueOfScope(session, rawScopes);
        if (scope == null) {
            return Stream.empty();
        }

        return scope.resolveOrganizations(userSession.getUser(), rawScopes, session);
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.ORGANIZATION);
    }

    public static ProtocolMapperModel create(String name, String samlAttributeName, String nameFormat, String friendlyName) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
        
        mapper.getConfig().put(AttributeStatementHelper.SAML_ATTRIBUTE_NAME, samlAttributeName);
        if (nameFormat != null) {
            mapper.getConfig().put(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT, nameFormat);
        }
        if (friendlyName != null) {
            mapper.getConfig().put(AttributeStatementHelper.FRIENDLY_NAME, friendlyName);
        }
        mapper.getConfig().put(ProtocolMapperUtils.MULTIVALUED, "true");
        
        return mapper;
    }
}