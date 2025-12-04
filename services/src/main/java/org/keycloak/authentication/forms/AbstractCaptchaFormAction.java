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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.captcha.CaptchaProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.utils.StringUtil;

/**
 * Abstract base class for CAPTCHA form actions.
 * Provides common implementation for buildPage() and validate() logic.
 * Subclasses only need to implement getCaptchaProvider() to specify which provider to use.
 */
public abstract class AbstractCaptchaFormAction implements FormAction, FormActionFactory {

    private static final Logger LOGGER = Logger.getLogger(AbstractCaptchaFormAction.class);

    private volatile KeycloakSessionFactory sessionFactory;

    /**
     * Get the CAPTCHA provider for this form action.
     * Subclasses should return the appropriate CaptchaProvider instance based on their configuration.
     *
     * @param session the Keycloak session
     * @param config the authenticator configuration
     * @return the CaptchaProvider instance, or null if not configured/available
     */
    protected abstract CaptchaProvider getCaptchaProvider(KeycloakSession session, Map<String, String> config);

    /**
     * Get the error message key to use when CAPTCHA is not configured.
     * Defaults to the generic CAPTCHA message, but can be overridden for backwards compatibility.
     *
     * @return the message key
     */
    protected String getNotConfiguredMessage() {
        return Messages.CAPTCHA_NOT_CONFIGURED;
    }

    /**
     * Get the error message key to use when CAPTCHA validation fails.
     * Defaults to the generic CAPTCHA message, but can be overridden for backwards compatibility.
     *
     * @return the message key
     */
    protected String getFailedMessage() {
        return Messages.CAPTCHA_FAILED;
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        LOGGER.trace("Building page with CAPTCHA");

        Map<String, String> config = null;
        if (context.getAuthenticatorConfig() != null) {
            config = context.getAuthenticatorConfig().getConfig();
        }

        if (config == null) {
            form.addError(new FormMessage(null, getNotConfiguredMessage()));
            return;
        }

        String providerId = config.get("captcha.provider");
        Map<String, String> providerConfig = extractProviderConfig(config, providerId);
        CaptchaProvider provider = getCaptchaProvider(context.getSession(), config);
        if (provider == null) {
            form.addError(new FormMessage(null, getNotConfiguredMessage()));
            return;
        }

        try {
            Map<String, Object> clientConfig = provider.getClientConfig(providerConfig,
                    context.getSession().getContext().resolveLocale(context.getUser()));

            // Add client config attributes to form
            for (Map.Entry<String, Object> entry : clientConfig.entrySet()) {
                form.setAttribute(entry.getKey(), entry.getValue());
            }

            // Add script using standard key
            String scriptUrl = (String) clientConfig.get("scriptUrl");
            if (scriptUrl != null) {
                form.addScript(scriptUrl);
            }
        } finally {
            provider.close();
        }
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String providerId = config.get("captcha.provider");
        Map<String, String> providerConfig = extractProviderConfig(config, providerId);

        CaptchaProvider provider = getCaptchaProvider(context.getSession(), config);
        if (provider == null) {
            List<FormMessage> errors = new ArrayList<>();
            errors.add(new FormMessage(null, getFailedMessage()));
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;
        }

        try {
            String captchaResponse = formData.getFirst(provider.getResponseFieldName());
            LOGGER.tracef("Got CAPTCHA response: %s", captchaResponse);

            if (!Validation.isBlank(captchaResponse)) {
                String remoteAddr = context.getConnection().getRemoteAddr();
                if (provider.verify(captchaResponse, remoteAddr, providerConfig)) {
                    context.success();
                    return;
                }
            }

            List<FormMessage> errors = new ArrayList<>();
            errors.add(new FormMessage(null, getFailedMessage()));
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
        } finally {
            provider.close();
        }
    }

    @Override
    public void success(FormContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public void close() {
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        this.sessionFactory = factory;
    }

    /**
     * Get the session factory. Safe to call after postInit() lifecycle method.
     * Subclasses can use this to access provider factories.
     *
     * @return the KeycloakSessionFactory instance
     */
    protected KeycloakSessionFactory getSessionFactory() {
        return sessionFactory;
    }

    /**
     * Extracts provider-specific configuration from the unified config map.
     * Properties prefixed with "{providerId}." are extracted and the prefix is stripped.
     *
     * @param config The full configuration map
     * @param providerId The provider ID (e.g., "recaptcha", "recaptcha-enterprise", "turnstile")
     * @return A new map containing only the provider-specific properties with prefixes removed
     */
    protected Map<String, String> extractProviderConfig(Map<String, String> config, String providerId) {
        if (config == null || StringUtil.isNullOrEmpty(providerId)) {
            return new HashMap<>();
        }

        Map<String, String> providerConfig = new HashMap<>();
        String prefix = providerId + ".";

        for (Map.Entry<String, String> entry : config.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(prefix)) {
                // Strip the provider prefix from the key
                String strippedKey = key.substring(prefix.length());
                providerConfig.put(strippedKey, entry.getValue());
            }
        }

        return providerConfig;
    }
}
