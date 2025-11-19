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

import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.captcha.CaptchaProvider;
import org.keycloak.captcha.CaptchaProviderFactory;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.utils.StringUtil;

import org.jboss.logging.Logger;

/**
 * Username/Password form with CAPTCHA support using pluggable CaptchaProvider.
 * Replaces UsernamePasswordFormWithTurnstile and similar implementations.
 */
public class UsernamePasswordFormWithCaptcha extends UsernamePasswordForm {

    private static final Logger LOGGER = Logger.getLogger(UsernamePasswordFormWithCaptcha.class);

    public UsernamePasswordFormWithCaptcha(KeycloakSession session) {
        super(session);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        // Check if this is a WebAuthn/passkey submission first
        // Passkey submissions should bypass CAPTCHA validation since the user didn't interact with the form
        if (webauthnAuth != null && webauthnAuth.isPasskeysEnabled()
                && (formData.containsKey(WebAuthnConstants.AUTHENTICATOR_DATA) || formData.containsKey(WebAuthnConstants.ERROR))) {
            // webauth form submission, try to action using the webauthn authenticator
            webauthnAuth.action(context);
            return;
        }

        // Validate CAPTCHA for normal username/password submissions
        if (context.getAuthenticatorConfig() != null) {
            Map<String, String> config = context.getAuthenticatorConfig().getConfig();
            String providerId = config.get("captcha.provider");
            Map<String, String> providerConfig = extractProviderConfig(config, providerId);
            CaptchaProvider provider = getCaptchaProvider(context.getSession(), config);

            if (provider != null) {
                try {
                    String captchaResponse = formData.getFirst(provider.getResponseFieldName());

                    if (Validation.isBlank(captchaResponse) || !provider.verify(captchaResponse,
                            context.getConnection().getRemoteAddr(), providerConfig)) {
                        context.getEvent().error(org.keycloak.events.Errors.INVALID_USER_CREDENTIALS);
                        Response challengeResponse = challenge(context, Messages.CAPTCHA_FAILED);
                        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
                        return;
                    }
                } finally {
                    provider.close();
                }
            }
        }

        // Continue with normal username/password validation
        super.action(context);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider form = context.form();
        addCaptchaToForm(context, form);
        if (formData != null && !formData.isEmpty()) {
            form.setFormData(formData);
        }
        return form.createLoginUsernamePassword();
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        // Keep WebAuthn/passkeys behavior aligned with base class
        if (isConditionalPasskeysEnabled(context.getUser())) {
            webauthnAuth.fillContextForm(context);
        }

        LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId());

        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }

        addCaptchaToForm(context, form);
        return createLoginForm(form);
    }

    private void addCaptchaToForm(AuthenticationFlowContext context, LoginFormsProvider form) {
        if (context.getAuthenticatorConfig() == null) {
            return;
        }

        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String providerId = config.get("captcha.provider");
        Map<String, String> providerConfig = extractProviderConfig(config, providerId);
        CaptchaProvider provider = getCaptchaProvider(context.getSession(), config);

        if (provider != null) {
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
    }

    private CaptchaProvider getCaptchaProvider(KeycloakSession session, Map<String, String> config) {
        if (config == null || session == null) {
            return null;
        }

        String providerId = config.get("captcha.provider");
        if (StringUtil.isNullOrEmpty(providerId)) {
            return null;
        }

        CaptchaProviderFactory factory = (CaptchaProviderFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(CaptchaProvider.class, providerId);

        if (factory == null) {
            LOGGER.warnf("CAPTCHA provider not found: %s", providerId);
            return null;
        }

        Map<String, String> providerConfig = extractProviderConfig(config, providerId);
        if (!factory.validateConfig(providerConfig)) {
            return null;
        }

        return factory.create(session);
    }

    /**
     * Extracts provider-specific configuration from the unified config map.
     * Properties prefixed with "{providerId}." are extracted and the prefix is stripped.
     *
     * @param config The full configuration map
     * @param providerId The provider ID (e.g., "recaptcha", "recaptcha-enterprise", "turnstile")
     * @return A new map containing only the provider-specific properties with prefixes removed
     */
    private Map<String, String> extractProviderConfig(Map<String, String> config, String providerId) {
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
