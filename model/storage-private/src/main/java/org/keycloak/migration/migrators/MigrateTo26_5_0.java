/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak.migration.migrators;

import java.util.HashMap;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.migration.ModelVersion;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Migration for version 26.5.0 - Migrates legacy reCAPTCHA authenticators to unified CAPTCHA abstraction.
 *
 * This migration consolidates the old provider-specific reCAPTCHA authenticators
 * (registration-recaptcha-action, registration-recaptcha-enterprise-action) into the new
 * unified CAPTCHA authenticator (registration-captcha-action) that supports multiple providers.
 */
public class MigrateTo26_5_0 extends RealmMigration {

    private static final Logger LOG = Logger.getLogger(MigrateTo26_5_0.class);

    public static final ModelVersion VERSION = new ModelVersion("26.5.0");

    // Old authenticator provider IDs
    private static final String OLD_RECAPTCHA = "registration-recaptcha-action";
    private static final String OLD_RECAPTCHA_ENTERPRISE = "registration-recaptcha-enterprise-action";

    // New unified authenticator provider ID
    private static final String NEW_CAPTCHA = "registration-captcha-action";

    // Configuration key for CAPTCHA provider selection
    private static final String CAPTCHA_PROVIDER_CONFIG_KEY = "captcha.provider";

    // CAPTCHA provider IDs for the abstraction layer
    private static final String RECAPTCHA_PROVIDER = "recaptcha";
    private static final String RECAPTCHA_ENTERPRISE_PROVIDER = "recaptcha-enterprise";

    @Override
    public void migrateRealm(KeycloakSession session, RealmModel realm) {
        migrateCaptchaAuthenticators(realm);
    }

    /**
     * Migrates all reCAPTCHA authenticator executions to use the unified CAPTCHA authenticator.
     * Preserves all existing configuration and maps to the appropriate CAPTCHA provider.
     */
    private void migrateCaptchaAuthenticators(RealmModel realm) {
        realm.getAuthenticationFlowsStream().forEach(flow -> {
            realm.getAuthenticationExecutionsStream(flow.getId())
                    .filter(execution -> OLD_RECAPTCHA.equals(execution.getAuthenticator()) ||
                            OLD_RECAPTCHA_ENTERPRISE.equals(execution.getAuthenticator()))
                    .forEach(execution -> {
                        String oldAuthenticator = execution.getAuthenticator();
                        String targetProvider = determineTargetProvider(oldAuthenticator);

                        // Update the authenticator provider ID to the new unified one
                        execution.setAuthenticator(NEW_CAPTCHA);

                        // Migrate the configuration to include the provider selection
                        if (execution.getAuthenticatorConfig() != null) {
                            AuthenticatorConfigModel config = realm.getAuthenticatorConfigById(execution.getAuthenticatorConfig());
                            if (config != null) {
                                migrateAuthenticatorConfig(realm, config, targetProvider);
                            }
                        } else {
                            // If no config exists, create one with the provider selection
                            createAuthenticatorConfig(realm, execution, targetProvider);
                        }

                        realm.updateAuthenticatorExecution(execution);

                        LOG.infof("Migrated authenticator '%s' to '%s' with provider '%s' in flow '%s' for realm '%s'.",
                                oldAuthenticator, NEW_CAPTCHA, targetProvider, flow.getAlias(), realm.getName());
                    });
        });
    }

    /**
     * Determines which CAPTCHA provider to use based on the old authenticator ID.
     */
    private String determineTargetProvider(String oldAuthenticator) {
        if (OLD_RECAPTCHA_ENTERPRISE.equals(oldAuthenticator)) {
            return RECAPTCHA_ENTERPRISE_PROVIDER;
        }
        return RECAPTCHA_PROVIDER;
    }

    /**
     * Updates an existing authenticator configuration to include the CAPTCHA provider selection.
     * All existing configuration properties are preserved as they are compatible with the new abstraction.
     */
    private void migrateAuthenticatorConfig(RealmModel realm, AuthenticatorConfigModel config, String targetProvider) {
        Map<String, String> updatedConfig = new HashMap<>(config.getConfig());
        updatedConfig.put(CAPTCHA_PROVIDER_CONFIG_KEY, targetProvider);
        config.setConfig(updatedConfig);
        realm.updateAuthenticatorConfig(config);

        LOG.debugf("Updated authenticator config '%s' to use provider '%s'.", config.getAlias(), targetProvider);
    }

    /**
     * Creates a new authenticator configuration when one doesn't exist.
     * This ensures the new unified authenticator has the necessary provider selection.
     */
    private void createAuthenticatorConfig(RealmModel realm, org.keycloak.models.AuthenticationExecutionModel execution, String targetProvider) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setAlias("CAPTCHA Config - " + targetProvider);

        Map<String, String> configMap = new HashMap<>();
        configMap.put(CAPTCHA_PROVIDER_CONFIG_KEY, targetProvider);
        config.setConfig(configMap);

        config = realm.addAuthenticatorConfig(config);
        execution.setAuthenticatorConfig(config.getId());

        LOG.debugf("Created new authenticator config for provider '%s' in realm '%s'.", targetProvider, realm.getName());
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }
}
