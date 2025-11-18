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

import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;

/**
 * Factory interface for creating CaptchaProvider instances.
 * Implementations should define their provider-specific configuration properties.
 */
public interface CaptchaProviderFactory extends ProviderFactory<CaptchaProvider>, ConfiguredProvider {

    /**
     * Gets the display name for this CAPTCHA provider.
     * This is shown in the admin console when selecting a CAPTCHA provider.
     *
     * @return the display name (e.g., "Google reCAPTCHA v2", "Cloudflare Turnstile")
     */
    String getDisplayName();

    /**
     * Gets the configuration properties specific to this CAPTCHA provider.
     * These are rendered in the admin console for configuration.
     *
     * @return list of configuration properties
     */
    List<ProviderConfigProperty> getConfigProperties();

    /**
     * Validates that the required configuration is present.
     *
     * @param config the configuration map
     * @return true if configuration is valid, false otherwise
     */
    boolean validateConfig(java.util.Map<String, String> config);
}
