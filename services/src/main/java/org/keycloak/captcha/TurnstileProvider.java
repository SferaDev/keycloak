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

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/**
 * Cloudflare Turnstile provider implementation.
 */
public class TurnstileProvider implements CaptchaProvider {

    private static final Logger LOGGER = Logger.getLogger(TurnstileProvider.class);
    private static final String REFERENCE_CATEGORY = "turnstile";
    private static final String RESPONSE_FIELD_NAME = "cf-turnstile-response";
    private static final String TURNSTILE_SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js";
    private static final String TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    private final KeycloakSession session;

    public TurnstileProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean verify(String response, String remoteAddr, Map<String, String> config) {
        LOGGER.trace("Verifying Turnstile using Cloudflare API");

        String secret = config.get(TurnstileProviderFactory.SECRET_KEY);
        return CaptchaHttpVerifier.verifyFormPost(session, TURNSTILE_VERIFY_URL, secret, response, remoteAddr);
    }

    @Override
    public Map<String, Object> getClientConfig(Map<String, String> config, Locale locale) {
        Map<String, Object> clientConfig = new HashMap<>();

        String siteKey = config.get(TurnstileProviderFactory.SITE_KEY);
        String action = config.get(TurnstileProviderFactory.ACTION);
        String theme = config.get(TurnstileProviderFactory.THEME);
        String size = config.get(TurnstileProviderFactory.SIZE);

        clientConfig.put("turnstileRequired", true);
        clientConfig.put("turnstileSiteKey", siteKey);
        clientConfig.put("turnstileAction", !StringUtil.isNullOrEmpty(action) ? action : TurnstileProviderFactory.DEFAULT_ACTION_REGISTER);
        clientConfig.put("turnstileTheme", !StringUtil.isNullOrEmpty(theme) ? theme : TurnstileProviderFactory.DEFAULT_THEME);
        clientConfig.put("turnstileSize", !StringUtil.isNullOrEmpty(size) ? size : TurnstileProviderFactory.DEFAULT_SIZE);
        clientConfig.put("turnstileLanguage", locale.toLanguageTag());

        // Standard key for script URL (used by AbstractCaptchaFormAction)
        clientConfig.put("scriptUrl", TURNSTILE_SCRIPT_URL);
        // Legacy key for backwards compatibility
        clientConfig.put("turnstileScriptUrl", TURNSTILE_SCRIPT_URL);

        return clientConfig;
    }

    @Override
    public String getResponseFieldName() {
        return RESPONSE_FIELD_NAME;
    }

    @Override
    public String getReferenceCategory() {
        return REFERENCE_CATEGORY;
    }

    @Override
    public void close() {
    }
}
