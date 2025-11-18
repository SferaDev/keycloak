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
 * Factory for creating Cloudflare Turnstile provider instances.
 */
public class TurnstileProviderFactory implements CaptchaProviderFactory {

    public static final String PROVIDER_ID = "turnstile";

    // Configuration keys
    public static final String SITE_KEY = "site.key";
    public static final String SECRET_KEY = "secret.key";
    public static final String ACTION = "action";
    public static final String THEME = "theme";
    public static final String SIZE = "size";

    // Default configuration values
    public static final String DEFAULT_ACTION_REGISTER = "register";
    public static final String DEFAULT_ACTION_LOGIN = "login";
    public static final String DEFAULT_ACTION_RESET = "reset";
    public static final String DEFAULT_THEME = "auto";
    public static final String DEFAULT_SIZE = "normal";

    @Override
    public CaptchaProvider create(KeycloakSession session) {
        return new TurnstileProvider(session);
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
        return "Cloudflare Turnstile";
    }

    @Override
    public String getHelpText() {
        return "Cloudflare Turnstile CAPTCHA integration.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(SITE_KEY)
                .label("Turnstile Site Key")
                .helpText("The site key from Cloudflare Turnstile.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(SECRET_KEY)
                .label("Turnstile Secret")
                .helpText("The secret key from Cloudflare Turnstile.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .secret(true)
                .add()
                .property()
                .name(ACTION)
                .label("Action Name")
                .helpText("A meaningful name for this Turnstile context (e.g. login, register).")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_ACTION_REGISTER)
                .add()
                .property()
                .name(THEME)
                .label("Theme")
                .helpText("The theme for the Turnstile widget.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("auto", "light", "dark")
                .defaultValue(DEFAULT_THEME)
                .add()
                .property()
                .name(SIZE)
                .label("Size")
                .helpText("The size of the Turnstile widget.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("normal", "flexible", "compact")
                .defaultValue(DEFAULT_SIZE)
                .add()
                .build();
    }

    @Override
    public boolean validateConfig(Map<String, String> config) {
        return config != null &&
                !StringUtil.isNullOrEmpty(config.get(SITE_KEY)) &&
                !StringUtil.isNullOrEmpty(config.get(SECRET_KEY));
    }
}
