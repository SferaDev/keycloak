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
import java.util.LinkedList;
import java.util.List;
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
 * Common utility class for CAPTCHA HTTP verification.
 * Provides shared logic for making form-encoded POST requests to CAPTCHA verification endpoints.
 */
public class CaptchaHttpVerifier {

    private static final Logger LOGGER = Logger.getLogger(CaptchaHttpVerifier.class);

    /**
     * Verifies a CAPTCHA response by making a form-encoded POST request to the verification URL.
     *
     * @param session the Keycloak session
     * @param verificationUrl the URL to POST the verification request to
     * @param secret the CAPTCHA provider secret key
     * @param response the CAPTCHA response token from the client
     * @param remoteAddr the client's remote IP address (may be null)
     * @return true if verification succeeds, false otherwise
     */
    public static boolean verifyFormPost(KeycloakSession session, String verificationUrl,
                                          String secret, String response, String remoteAddr) {
        LOGGER.tracef("Verifying CAPTCHA at URL: %s", verificationUrl);

        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost(verificationUrl);

        List<NameValuePair> formparams = new LinkedList<>();
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
                    boolean success = Boolean.TRUE.equals(json.get("success"));

                    if (!success && LOGGER.isDebugEnabled()) {
                        LOGGER.debugf("CAPTCHA verification failed. Response: %s", json);
                    }

                    return success;
                } finally {
                    EntityUtils.consumeQuietly(httpResponse.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.captchaFailed(e);
            return false;
        }
    }

    /**
     * Verifies a CAPTCHA response with additional form parameters.
     *
     * @param session the Keycloak session
     * @param verificationUrl the URL to POST the verification request to
     * @param formParameters additional form parameters to include in the request
     * @return true if verification succeeds, false otherwise
     */
    public static boolean verifyFormPostWithParams(KeycloakSession session, String verificationUrl,
                                                     List<NameValuePair> formParameters) {
        LOGGER.tracef("Verifying CAPTCHA at URL: %s", verificationUrl);

        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost(verificationUrl);

        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formParameters, StandardCharsets.UTF_8);
            post.setEntity(form);

            try (CloseableHttpResponse httpResponse = httpClient.execute(post)) {
                InputStream content = httpResponse.getEntity().getContent();
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> json = JsonSerialization.readValue(content, Map.class);
                    boolean success = Boolean.TRUE.equals(json.get("success"));

                    if (!success && LOGGER.isDebugEnabled()) {
                        LOGGER.debugf("CAPTCHA verification failed. Response: %s", json);
                    }

                    return success;
                } finally {
                    EntityUtils.consumeQuietly(httpResponse.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.captchaFailed(e);
            return false;
        }
    }
}
