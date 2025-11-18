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

package org.keycloak.captcha;

import java.util.List;
import java.util.Map;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

/**
 * Factory for creating Google reCAPTCHA v2/v3 provider instances.
 */
public class RecaptchaProviderFactory implements CaptchaProviderFactory {

    public static final String PROVIDER_ID = "recaptcha";

    // Configuration keys
    public static final String SITE_KEY = "site.key";
    public static final String SECRET_KEY = "secret.key";
    public static final String OLD_SECRET = "secret"; // Legacy key name
    public static final String ACTION = "action";
    public static final String INVISIBLE = "recaptcha.v3";
    public static final String USE_RECAPTCHA_NET = "useRecaptchaNet";

    @Override
    public CaptchaProvider create(KeycloakSession session) {
        return new RecaptchaProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayName() {
        return "Google reCAPTCHA v2/v3";
    }

    @Override
    public String getHelpText() {
        return "Google reCAPTCHA v2 (checkbox) or v3 (invisible, score-based) integration.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(SITE_KEY)
                .label("reCAPTCHA Site Key")
                .helpText("The site key from Google reCAPTCHA.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(SECRET_KEY)
                .label("reCAPTCHA Secret")
                .helpText("The secret key from Google reCAPTCHA.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .secret(true)
                .add()
                .property()
                .name(ACTION)
                .label("Action Name")
                .helpText("A meaningful name for this reCAPTCHA context (e.g. login, register). "
                        + "An action name can only contain alphanumeric characters, "
                        + "slashes and underscores and is not case-sensitive.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("register")
                .add()
                .property()
                .name(USE_RECAPTCHA_NET)
                .label("Use recaptcha.net")
                .helpText("Whether to use recaptcha.net instead of google.com, "
                        + "which may have other cookies set.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(false)
                .add()
                .property()
                .name(INVISIBLE)
                .label("reCAPTCHA v3")
                .helpText("Whether the site key belongs to a v3 (invisible, score-based reCAPTCHA) "
                        + "or v2 site (visible, checkbox-based).")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(false)
                .add()
                .build();
    }

    @Override
    public boolean validateConfig(Map<String, String> config) {
        return !StringUtil.isNullOrEmpty(config.get(SITE_KEY)) &&
                !StringUtil.isNullOrEmpty(getSecretKey(config));
    }

    /**
     * Gets the secret key from config, checking both new and legacy key names.
     * This method handles backwards compatibility with the old "secret" config key.
     *
     * @param config the configuration map
     * @return the secret key, or null if not found
     */
    public static String getSecretKey(Map<String, String> config) {
        String secret = config.get(SECRET_KEY);
        if (StringUtil.isNullOrEmpty(secret)) {
            // Try legacy secret key for backwards compatibility
            secret = config.get(OLD_SECRET);
        }
        return secret;
    }
}
