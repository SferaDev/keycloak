/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.authentication.authenticators.browser;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Factory for creating UsernamePasswordFormWithCaptcha authenticator instances.
 * Provides a unified CAPTCHA-enabled login form that works with any CaptchaProvider.
 */
public class UsernamePasswordFormWithCaptchaFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-username-password-form-captcha";

    private static final String CAPTCHA_PROVIDER = "captcha.provider";

    private KeycloakSessionFactory sessionFactory;

    @Override
    public String getDisplayType() {
        return "Username Password Form with CAPTCHA";
    }

    @Override
    public String getReferenceCategory() {
        return "captcha";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from login form with CAPTCHA verification.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

        // Get all registered CAPTCHA provider factories dynamically
        List<String> providerIds = sessionFactory.getProviderFactoriesStream(org.keycloak.captcha.CaptchaProvider.class)
                .map(org.keycloak.provider.ProviderFactory::getId)
                .toList();

        // Add the provider selector
        builder.property()
                .name(CAPTCHA_PROVIDER)
                .label("CAPTCHA Provider")
                .helpText("Select the CAPTCHA provider to use. Configure the provider-specific settings below.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(providerIds)
                .defaultValue(providerIds.isEmpty() ? null : providerIds.get(0))
                .add();

        // Add all provider-specific properties dynamically
        // These will be shown/hidden in the admin console based on the selected provider
        sessionFactory.getProviderFactoriesStream(org.keycloak.captcha.CaptchaProvider.class)
                .filter(factory -> factory instanceof org.keycloak.captcha.CaptchaProviderFactory)
                .forEach(factory -> {
                    org.keycloak.captcha.CaptchaProviderFactory captchaFactory = (org.keycloak.captcha.CaptchaProviderFactory) factory;
                    String providerId = factory.getId();

                    // Get properties from the provider factory and prefix them
                    for (ProviderConfigProperty property : captchaFactory.getConfigProperties()) {
                        builder.property()
                                .name(providerId + "." + property.getName())
                                .label(property.getLabel())
                                .helpText(property.getHelpText())
                                .type(property.getType())
                                .defaultValue(property.getDefaultValue())
                                .secret(property.isSecret())
                                .options(property.getOptions())
                                .add();
                    }
                });

        return builder.build();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new UsernamePasswordFormWithCaptcha(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        this.sessionFactory = factory;
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
