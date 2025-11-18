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

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.JsonSerialization;

/**
 * Google reCAPTCHA v2/v3 provider implementation.
 */
public class RecaptchaProvider implements CaptchaProvider {

    private static final Logger LOGGER = Logger.getLogger(RecaptchaProvider.class);
    private static final String REFERENCE_CATEGORY = "recaptcha";
    private static final String RESPONSE_FIELD_NAME = "g-recaptcha-response";

    private final KeycloakSession session;

    public RecaptchaProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean verify(String response, String remoteAddr, Map<String, String> config) {
        LOGGER.trace("Verifying reCAPTCHA using non-enterprise API");
        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();

        String domain = Boolean.parseBoolean(config.get(RecaptchaProviderFactory.USE_RECAPTCHA_NET))
                ? "recaptcha.net" : "google.com";
        HttpPost post = new HttpPost("https://www." + domain + "/recaptcha/api/siteverify");
        List<NameValuePair> formparams = new LinkedList<>();

        // Use factory helper to get secret key (handles backwards compatibility)
        String secret = RecaptchaProviderFactory.getSecretKey(config);

        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", response));
        if (remoteAddr != null) {
            formparams.add(new BasicNameValuePair("remoteip", remoteAddr));
        }

        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, StandardCharsets.UTF_8);
            post.setEntity(form);
            try (CloseableHttpResponse httpResponse = httpClient.execute(post)) {
                InputStream content = httpResponse.getEntity().getContent();
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> json = JsonSerialization.readValue(content, Map.class);
                    return Boolean.TRUE.equals(json.get("success"));
                } finally {
                    EntityUtils.consumeQuietly(httpResponse.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.captchaFailed(e);
        }
        return false;
    }

    @Override
    public Map<String, Object> getClientConfig(Map<String, String> config, Locale locale) {
        Map<String, Object> clientConfig = new HashMap<>();

        String siteKey = config.get(RecaptchaProviderFactory.SITE_KEY);
        String action = config.get(RecaptchaProviderFactory.ACTION);
        boolean invisible = Boolean.parseBoolean(config.get(RecaptchaProviderFactory.INVISIBLE));
        String domain = Boolean.parseBoolean(config.get(RecaptchaProviderFactory.USE_RECAPTCHA_NET))
                ? "recaptcha.net" : "google.com";

        clientConfig.put("recaptchaRequired", true);
        clientConfig.put("recaptchaSiteKey", siteKey);
        clientConfig.put("recaptchaAction", action != null ? action : "register");
        clientConfig.put("recaptchaVisible", !invisible);

        String languageTag = locale.toLanguageTag();
        String scriptUrl = "https://www." + domain + "/recaptcha/api.js?hl=" + languageTag;

        // Standard key for script URL (used by AbstractCaptchaFormAction)
        clientConfig.put("scriptUrl", scriptUrl);
        // Legacy key for backwards compatibility
        clientConfig.put("recaptchaScriptUrl", scriptUrl);

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
