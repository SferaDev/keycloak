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

package org.keycloak.authentication.authenticators.util;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for TurnstileHelper configuration validation
 */
public class TurnstileHelperTest {

    @Test
    public void testValidateConfig_WithValidConfig() {
        Map<String, String> config = new HashMap<>();
        config.put(TurnstileHelper.SITE_KEY, "test-site-key");
        config.put(TurnstileHelper.SECRET_KEY, "test-secret-key");

        assertTrue(TurnstileHelper.validateConfig(config));
    }

    @Test
    public void testValidateConfig_WithNullConfig() {
        assertFalse(TurnstileHelper.validateConfig(null));
    }

    @Test
    public void testValidateConfig_WithMissingSiteKey() {
        Map<String, String> config = new HashMap<>();
        config.put(TurnstileHelper.SECRET_KEY, "test-secret-key");

        assertFalse(TurnstileHelper.validateConfig(config));
    }

    @Test
    public void testValidateConfig_WithMissingSecretKey() {
        Map<String, String> config = new HashMap<>();
        config.put(TurnstileHelper.SITE_KEY, "test-site-key");

        assertFalse(TurnstileHelper.validateConfig(config));
    }

    @Test
    public void testValidateConfig_WithEmptySiteKey() {
        Map<String, String> config = new HashMap<>();
        config.put(TurnstileHelper.SITE_KEY, "");
        config.put(TurnstileHelper.SECRET_KEY, "test-secret-key");

        assertFalse(TurnstileHelper.validateConfig(config));
    }

    @Test
    public void testValidateConfig_WithEmptySecretKey() {
        Map<String, String> config = new HashMap<>();
        config.put(TurnstileHelper.SITE_KEY, "test-site-key");
        config.put(TurnstileHelper.SECRET_KEY, "");

        assertFalse(TurnstileHelper.validateConfig(config));
    }

    @Test
    public void testValidateActionName_WithValidNames() {
        assertTrue(TurnstileHelper.validateActionName("login"));
        assertTrue(TurnstileHelper.validateActionName("register"));
        assertTrue(TurnstileHelper.validateActionName("reset"));
        assertTrue(TurnstileHelper.validateActionName("login_user"));
        assertTrue(TurnstileHelper.validateActionName("auth/login"));
        assertTrue(TurnstileHelper.validateActionName("user_registration"));
        assertTrue(TurnstileHelper.validateActionName("API_ACCESS_123"));
    }

    @Test
    public void testValidateActionName_WithInvalidNames() {
        assertFalse(TurnstileHelper.validateActionName(null));
        assertFalse(TurnstileHelper.validateActionName(""));
        assertFalse(TurnstileHelper.validateActionName("login-user")); // hyphen not allowed
        assertFalse(TurnstileHelper.validateActionName("login.user")); // dot not allowed
        assertFalse(TurnstileHelper.validateActionName("login user")); // space not allowed
        assertFalse(TurnstileHelper.validateActionName("login@user")); // special char not allowed
        assertFalse(TurnstileHelper.validateActionName("login#123")); // special char not allowed
    }

    @Test
    public void testConstants() {
        assertEquals("cf-turnstile-response", TurnstileHelper.CF_TURNSTILE_RESPONSE);
        assertEquals("site.key", TurnstileHelper.SITE_KEY);
        assertEquals("secret.key", TurnstileHelper.SECRET_KEY);
        assertEquals("action", TurnstileHelper.ACTION);
        assertEquals("theme", TurnstileHelper.THEME);
        assertEquals("size", TurnstileHelper.SIZE);
        assertEquals("https://challenges.cloudflare.com/turnstile/v0/api.js", TurnstileHelper.TURNSTILE_SCRIPT_URL);
        assertEquals("https://challenges.cloudflare.com/turnstile/v0/siteverify", TurnstileHelper.TURNSTILE_VERIFY_URL);
        assertEquals("register", TurnstileHelper.DEFAULT_ACTION_REGISTER);
        assertEquals("login", TurnstileHelper.DEFAULT_ACTION_LOGIN);
        assertEquals("reset", TurnstileHelper.DEFAULT_ACTION_RESET);
        assertEquals("auto", TurnstileHelper.DEFAULT_THEME);
        assertEquals("normal", TurnstileHelper.DEFAULT_SIZE);
        assertEquals("turnstile", TurnstileHelper.TURNSTILE_REFERENCE_CATEGORY);
    }
}
