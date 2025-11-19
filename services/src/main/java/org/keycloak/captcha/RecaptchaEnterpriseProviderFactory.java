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
import java.util.stream.Stream;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

/**
 * Factory for creating Google reCAPTCHA Enterprise provider instances.
 */
public class RecaptchaEnterpriseProviderFactory implements CaptchaProviderFactory {

    public static final String PROVIDER_ID = "recaptcha-enterprise";

    // Configuration keys
    public static final String PROJECT_ID = "project.id";
    public static final String SITE_KEY = "site.key";
    public static final String API_KEY = "api.key";
    public static final String ACTION = "action";
    public static final String SCORE_THRESHOLD = "score.threshold";
    public static final String INVISIBLE = "recaptcha.v3";
    public static final String USE_RECAPTCHA_NET = "useRecaptchaNet";

    @Override
    public CaptchaProvider create(KeycloakSession session) {
        return new RecaptchaEnterpriseProvider(session);
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
        return "Google reCAPTCHA Enterprise";
    }

    @Override
    public String getHelpText() {
        return "Google reCAPTCHA Enterprise with risk analysis and score-based assessment.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(PROJECT_ID)
                .label("Project ID")
                .helpText("Project ID the site key belongs to.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(SITE_KEY)
                .label("reCAPTCHA Site Key")
                .helpText("The site key from Google reCAPTCHA Enterprise.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(API_KEY)
                .label("Google API Key")
                .helpText("An API key with the reCAPTCHA Enterprise API enabled in the given project ID.")
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
                .name(SCORE_THRESHOLD)
                .label("Min. Score Threshold")
                .helpText("The minimum score threshold for considering the reCAPTCHA valid (inclusive). "
                        + "Must be a valid double between 0.0 and 1.0.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("0.7")
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
        return !(Stream.of(PROJECT_ID, SITE_KEY, API_KEY, ACTION)
                .anyMatch(key -> StringUtil.isNullOrEmpty(config.get(key)))
                || parseDoubleFromConfig(config, SCORE_THRESHOLD) == null);
    }

    private Double parseDoubleFromConfig(Map<String, String> config, String key) {
        String value = config.getOrDefault(key, "");
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
