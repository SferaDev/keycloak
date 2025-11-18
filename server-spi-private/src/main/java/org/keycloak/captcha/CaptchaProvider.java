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

import java.util.Locale;
import java.util.Map;

import org.keycloak.provider.Provider;

/**
 * Provider interface for CAPTCHA verification services.
 * Allows pluggable integration with different CAPTCHA solutions (reCAPTCHA, Turnstile, hCaptcha, etc.).
 */
public interface CaptchaProvider extends Provider {

    /**
     * Verifies a CAPTCHA response from the client.
     *
     * @param response the CAPTCHA response token from the client
     * @param remoteAddr the client's remote IP address (may be null)
     * @param config the provider-specific configuration
     * @return true if verification succeeds, false otherwise
     */
    boolean verify(String response, String remoteAddr, Map<String, String> config);

    /**
     * Gets the client-side configuration needed to render the CAPTCHA widget.
     * This includes things like script URLs, site keys, theme settings, etc.
     *
     * @param config the provider-specific configuration
     * @param locale the user's locale for internationalization
     * @return a map of attributes to pass to the form template
     */
    Map<String, Object> getClientConfig(Map<String, String> config, Locale locale);

    /**
     * Gets the name of the form field that contains the CAPTCHA response token.
     * This field name is used when extracting the response from form submissions.
     *
     * @return the form field name (e.g., "g-recaptcha-response", "cf-turnstile-response")
     */
    String getResponseFieldName();

    /**
     * Gets the reference category for this CAPTCHA provider.
     * Used for grouping related authenticators in the admin console.
     *
     * @return the reference category (e.g., "recaptcha", "turnstile")
     */
    String getReferenceCategory();
}
