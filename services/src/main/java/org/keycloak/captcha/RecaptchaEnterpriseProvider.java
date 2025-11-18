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

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.forms.RecaptchaAssessmentRequest;
import org.keycloak.authentication.forms.RecaptchaAssessmentResponse;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.JsonSerialization;

/**
 * Google reCAPTCHA Enterprise provider implementation.
 */
public class RecaptchaEnterpriseProvider implements CaptchaProvider {

    private static final Logger LOGGER = Logger.getLogger(RecaptchaEnterpriseProvider.class);
    private static final String REFERENCE_CATEGORY = "recaptcha";
    private static final String RESPONSE_FIELD_NAME = "g-recaptcha-response";

    private final KeycloakSession session;

    public RecaptchaEnterpriseProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean verify(String response, String remoteAddr, Map<String, String> config) {
        LOGGER.trace("Requesting assessment of Google reCAPTCHA Enterprise");
        try {
            HttpPost request = buildAssessmentRequest(response, config);
            HttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
            HttpResponse httpResponse = httpClient.execute(request);

            if (httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                LOGGER.errorf("Could not create reCAPTCHA assessment: %s", httpResponse.getStatusLine());
                EntityUtils.consumeQuietly(httpResponse.getEntity());
                throw new Exception(httpResponse.getStatusLine().getReasonPhrase());
            }

            RecaptchaAssessmentResponse assessment = JsonSerialization.readValue(
                    httpResponse.getEntity().getContent(), RecaptchaAssessmentResponse.class);
            LOGGER.tracef("Got assessment response: %s", assessment);

            String tokenAction = assessment.getTokenProperties().getAction();
            String expectedAction = assessment.getEvent().getExpectedAction();
            if (!tokenAction.equals(expectedAction)) {
                // This may indicate that an attacker is attempting to falsify actions
                LOGGER.warnf("The action name of the reCAPTCHA token '%s' does not match the expected action '%s'!",
                        tokenAction, expectedAction);
                return false;
            }

            boolean valid = assessment.getTokenProperties().isValid();
            double score = assessment.getRiskAnalysis().getScore();
            Double threshold = parseDoubleFromConfig(config, RecaptchaEnterpriseProviderFactory.SCORE_THRESHOLD);
            LOGGER.debugf("reCAPTCHA assessment: valid=%s, score=%f, threshold=%f", valid, score, threshold);

            return valid && threshold != null && score >= threshold;

        } catch (Exception e) {
            ServicesLogger.LOGGER.captchaFailed(e);
        }

        return false;
    }

    @Override
    public Map<String, Object> getClientConfig(Map<String, String> config, Locale locale) {
        Map<String, Object> clientConfig = new HashMap<>();

        String siteKey = config.get(RecaptchaEnterpriseProviderFactory.SITE_KEY);
        String action = config.get(RecaptchaEnterpriseProviderFactory.ACTION);
        boolean invisible = Boolean.parseBoolean(config.get(RecaptchaEnterpriseProviderFactory.INVISIBLE));
        String domain = Boolean.parseBoolean(config.get(RecaptchaEnterpriseProviderFactory.USE_RECAPTCHA_NET))
                ? "recaptcha.net" : "google.com";

        clientConfig.put("recaptchaRequired", true);
        clientConfig.put("recaptchaSiteKey", siteKey);
        clientConfig.put("recaptchaAction", action != null ? action : "register");
        clientConfig.put("recaptchaVisible", !invisible);

        String languageTag = locale.toLanguageTag();
        String scriptUrl = "https://www." + domain + "/recaptcha/enterprise.js?hl=" + languageTag;

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

    private HttpPost buildAssessmentRequest(String captcha, Map<String, String> config) throws IOException {
        String projectId = config.get(RecaptchaEnterpriseProviderFactory.PROJECT_ID);
        String apiKey = config.get(RecaptchaEnterpriseProviderFactory.API_KEY);
        String siteKey = config.get(RecaptchaEnterpriseProviderFactory.SITE_KEY);
        String action = config.get(RecaptchaEnterpriseProviderFactory.ACTION);

        String url = String.format("https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s",
                projectId, apiKey);

        HttpPost request = new HttpPost(url);
        RecaptchaAssessmentRequest body = new RecaptchaAssessmentRequest(captcha, siteKey, action);
        request.setEntity(new StringEntity(JsonSerialization.writeValueAsString(body)));
        request.setHeader("Content-type", "application/json; charset=utf-8");

        LOGGER.tracef("Built assessment request: %s", body);
        return request;
    }

    private Double parseDoubleFromConfig(Map<String, String> config, String key) {
        String value = config.getOrDefault(key, "");
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            LOGGER.warnf("Could not parse config %s as double: '%s'", key, value);
        }
        return null;
    }
}
