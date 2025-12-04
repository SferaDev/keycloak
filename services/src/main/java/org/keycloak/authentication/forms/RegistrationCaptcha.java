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

package org.keycloak.authentication.forms;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.captcha.CaptchaProvider;
import org.keycloak.captcha.CaptchaProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.utils.StringUtil;

/**
 * Unified CAPTCHA form action that supports multiple CAPTCHA providers.
 * Allows selecting any available CaptchaProvider via configuration.
 */
public class RegistrationCaptcha extends AbstractCaptchaFormAction {

    private static final Logger LOGGER = Logger.getLogger(RegistrationCaptcha.class);
    public static final String PROVIDER_ID = "registration-captcha-action";

    // Configuration keys
    public static final String CAPTCHA_PROVIDER = "captcha.provider";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "CAPTCHA";
    }

    @Override
    public String getHelpText() {
        return "Adds a configurable CAPTCHA to the registration form.";
    }

    @Override
    public String getReferenceCategory() {
        // Return a generic category since we don't have access to config here
        // The actual provider category will be used when the provider is instantiated
        return "captcha";
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

        // Get all registered CAPTCHA provider factories dynamically
        List<String> providerIds = getSessionFactory().getProviderFactoriesStream(org.keycloak.captcha.CaptchaProvider.class)
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
        getSessionFactory().getProviderFactoriesStream(org.keycloak.captcha.CaptchaProvider.class)
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
    protected CaptchaProvider getCaptchaProvider(KeycloakSession session, Map<String, String> config) {
        if (config == null || session == null) {
            return null;
        }

        String providerId = config.get(CAPTCHA_PROVIDER);
        if (StringUtil.isNullOrEmpty(providerId)) {
            LOGGER.warn("No CAPTCHA provider configured");
            return null;
        }

        CaptchaProviderFactory factory = (CaptchaProviderFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(CaptchaProvider.class, providerId);

        if (factory == null) {
            LOGGER.warnf("CAPTCHA provider not found: %s", providerId);
            return null;
        }

        // Extract provider-specific config and validate
        Map<String, String> providerConfig = extractProviderConfig(config, providerId);
        if (!factory.validateConfig(providerConfig)) {
            LOGGER.warnf("Invalid configuration for CAPTCHA provider: %s", providerId);
            return null;
        }

        return factory.create(session);
    }
}
