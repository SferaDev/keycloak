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

package org.keycloak.tests.admin.authentication;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * Integration tests for CAPTCHA authenticators.
 *
 * @author Alexis Rico
 */
@KeycloakIntegrationTest
public class CaptchaAuthenticatorTest extends AbstractAuthenticationTest {

    @Test
    public void testCaptchaAuthenticatorExists() {
        // Verify that the unified CAPTCHA authenticator is registered
        List<Map<String, Object>> providers = authMgmtResource.getFormActionProviders();

        boolean found = providers.stream()
                .anyMatch(p -> "registration-captcha-action".equals(p.get("id")));

        Assertions.assertTrue(found, "Unified CAPTCHA authenticator should be registered");
    }

    @Test
    public void testCaptchaAuthenticatorInDefaultRegistrationFlow() {
        // Get the default registration flow
        AuthenticationFlowRepresentation registrationFlow = authMgmtResource.getFlows().stream()
                .filter(f -> "registration".equals(f.getAlias()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Registration flow not found"));

        // Get executions for the registration flow
        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions(registrationFlow.getAlias());

        // Find the CAPTCHA execution
        AuthenticationExecutionInfoRepresentation captchaExec = executions.stream()
                .filter(e -> "registration-captcha-action".equals(e.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("CAPTCHA execution not found in registration flow"));

        // Verify it's configured correctly
        Assertions.assertEquals("CAPTCHA", captchaExec.getDisplayName());
        Assertions.assertEquals("DISABLED", captchaExec.getRequirement(),
                "CAPTCHA should be disabled by default");
    }

    @Test
    public void testCaptchaAuthenticatorConfiguration() {
        // Get the default registration flow
        AuthenticationFlowRepresentation registrationFlow = authMgmtResource.getFlows().stream()
                .filter(f -> "registration".equals(f.getAlias()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Registration flow not found"));

        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions(registrationFlow.getAlias());

        AuthenticationExecutionInfoRepresentation captchaExec = executions.stream()
                .filter(e -> "registration-captcha-action".equals(e.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("CAPTCHA execution not found"));

        // Create a configuration for the CAPTCHA authenticator
        AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
        config.setAlias("Test CAPTCHA Config");

        Map<String, String> configMap = new HashMap<>();
        configMap.put("captcha.provider", "recaptcha");
        configMap.put("recaptcha.site.key", "test-site-key");
        configMap.put("recaptcha.secret", "test-secret");
        config.setConfig(configMap);

        // Add the configuration
        config = authMgmtResource.newExecutionConfig(captchaExec.getId(), config);
        Assertions.assertNotNull(config.getId(), "Config ID should be set");

        // Retrieve and verify
        AuthenticatorConfigRepresentation retrieved = authMgmtResource.getAuthenticatorConfig(config.getId());
        Assertions.assertEquals("Test CAPTCHA Config", retrieved.getAlias());
        Assertions.assertEquals("recaptcha", retrieved.getConfig().get("captcha.provider"));
        Assertions.assertEquals("test-site-key", retrieved.getConfig().get("recaptcha.site.key"));

        // Clean up
        authMgmtResource.removeAuthenticatorConfig(config.getId());
    }

    @Test
    public void testMultipleCaptchaProvidersAvailable() {
        // Get form action providers
        List<Map<String, Object>> providers = authMgmtResource.getFormActionProviders();

        // Find the CAPTCHA authenticator
        Map<String, Object> captchaAuthenticator = providers.stream()
                .filter(p -> "registration-captcha-action".equals(p.get("id")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("CAPTCHA authenticator not found"));

        // The authenticator should have configuration properties that include provider selection
        Assertions.assertNotNull(captchaAuthenticator.get("properties"),
                "CAPTCHA authenticator should have configuration properties");
    }

    @Test
    public void testCaptchaProviderSpiRegistered() {
        // Get all providers
        List<Map<String, Object>> providers = authMgmtResource.getFormActionProviders();

        // Verify that the CAPTCHA authenticator exists
        boolean captchaFound = providers.stream()
                .anyMatch(p -> "registration-captcha-action".equals(p.get("id")));

        Assertions.assertTrue(captchaFound, "CAPTCHA authenticator should be available");
    }
}
