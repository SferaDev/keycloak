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
package org.keycloak.testsuite.forms;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormWithTurnstileFactory;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUserWithTurnstileFactory;
import org.keycloak.authentication.authenticators.util.TurnstileHelper;
import org.keycloak.authentication.forms.RegistrationTurnstile;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.LoginPasswordResetPage;
import org.keycloak.testsuite.pages.RegisterPage;
import org.keycloak.testsuite.util.FlowUtil;

import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Integration tests for Cloudflare Turnstile CAPTCHA functionality.
 * Tests registration, login, and password reset flows with Turnstile protection.
 *
 * @author Alexis Rico
 */
public class TurnstileTest extends AbstractTestRealmKeycloakTest {

    // Cloudflare test keys that always pass validation
    // https://developers.cloudflare.com/turnstile/reference/testing/
    private static final String TEST_SITE_KEY = "1x00000000000000000000AA";
    private static final String TEST_SECRET_KEY = "1x0000000000000000000000000000000AA";

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Page
    protected AppPage appPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected RegisterPage registerPage;

    @Page
    protected ErrorPage errorPage;

    @Page
    protected LoginPasswordResetPage resetPasswordPage;

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    @Before
    public void cleanupFlows() {
        // Clean up any custom flows from previous tests
        List<AuthenticationFlowRepresentation> flows = testRealm().flows().getFlows();
        for (AuthenticationFlowRepresentation flow : flows) {
            if (flow.getAlias().equals("RegistrationWithTurnstile") ||
                flow.getAlias().equals("BrowserWithTurnstile") ||
                flow.getAlias().equals("ResetWithTurnstile")) {
                testRealm().flows().deleteFlow(flow.getId());
            }
        }
    }

    /**
     * Test that Turnstile widget is rendered on registration form when configured.
     */
    @Test
    public void testTurnstileOnRegistrationForm() {
        configureRegistrationFlowWithTurnstile();

        loginPage.open();
        loginPage.clickRegister();
        registerPage.assertCurrent();

        // Verify Turnstile widget is present
        String pageSource = driver.getPageSource();
        assertThat("Turnstile script should be loaded", pageSource, 
            containsString("challenges.cloudflare.com/turnstile/v0/api.js"));
        assertThat("Turnstile widget should be present", pageSource, 
            containsString("cf-turnstile"));
        assertThat("Site key should be configured", pageSource, 
            containsString(TEST_SITE_KEY));
    }

    /**
     * Test that registration fails without valid Turnstile response.
     */
    @Test
    public void testRegistrationFailsWithoutTurnstileResponse() {
        configureRegistrationFlowWithTurnstile();

        loginPage.open();
        loginPage.clickRegister();
        registerPage.assertCurrent();

        // Try to register without Turnstile response
        registerPage.register("firstName", "lastName", "test@test.com", 
            "test-user", "password", "password");

        registerPage.assertCurrent();
        String pageSource = driver.getPageSource();
        assertThat("Should show Turnstile error", pageSource, 
            containsString("Invalid Turnstile verification"));

        events.expectRegister("test-user", "test@test.com")
            .user((String) null)
            .error(Errors.INVALID_REGISTRATION)
            .assertEvent();
    }

    /**
     * Test that Turnstile configuration validation works.
     */
    @Test
    public void testTurnstileConfigurationValidation() {
        // Create flow with configuration missing the secret key
        String flowAlias = "RegistrationWithInvalidTurnstile";
        AuthenticationFlowRepresentation flow = FlowUtil.injectExecutionWithConfig(
            testRealm(),
            DefaultAuthenticationFlows.REGISTRATION_FLOW,
            flowAlias,
            RegistrationTurnstile.PROVIDER_ID,
            createTurnstileConfigWithoutSecretKey(),
            AuthenticationExecutionModel.Requirement.REQUIRED
        );

        // Set as registration flow
        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setRegistrationFlow(flowAlias);
        testRealm().update(realm);

        loginPage.open();
        loginPage.clickRegister();
        registerPage.assertCurrent();

        // Registration should show error about missing configuration
        String pageSource = driver.getPageSource();
        assertThat("Should show configuration error", pageSource,
            containsString("Turnstile is required, but not configured"));
    }

    /**
     * Test Turnstile on login form.
     */
    @Test
    public void testTurnstileOnLoginForm() {
        configureBrowserFlowWithTurnstile();

        loginPage.open();
        loginPage.assertCurrent();

        // Verify Turnstile widget is present
        String pageSource = driver.getPageSource();
        assertThat("Turnstile script should be loaded", pageSource,
            containsString("challenges.cloudflare.com/turnstile/v0/api.js"));
        assertThat("Turnstile widget should be present", pageSource,
            containsString("cf-turnstile"));
        assertThat("Site key should be configured", pageSource,
            containsString(TEST_SITE_KEY));
    }

    /**
     * Test that login fails without valid Turnstile response.
     */
    @Test
    public void testLoginFailsWithoutTurnstileResponse() {
        configureBrowserFlowWithTurnstile();

        loginPage.open();
        loginPage.assertCurrent();

        // Try to login without Turnstile response
        loginPage.login("test-user@localhost", "password");

        loginPage.assertCurrent();
        String pageSource = driver.getPageSource();
        assertThat("Should show Turnstile error", pageSource,
            containsString("Invalid Turnstile verification"));

        events.expectLogin()
            .user((String) null)
            .session((String) null)
            .error(Errors.INVALID_USER_CREDENTIALS)
            .assertEvent();
    }

    /**
     * Test Turnstile on password reset form.
     */
    @Test
    public void testTurnstileOnPasswordResetForm() {
        configureResetCredentialsFlowWithTurnstile();

        loginPage.open();
        loginPage.resetPassword();
        resetPasswordPage.assertCurrent();

        // Verify Turnstile widget is present
        String pageSource = driver.getPageSource();
        assertThat("Turnstile script should be loaded", pageSource,
            containsString("challenges.cloudflare.com/turnstile/v0/api.js"));
        assertThat("Turnstile widget should be present", pageSource,
            containsString("cf-turnstile"));
        assertThat("Site key should be configured", pageSource,
            containsString(TEST_SITE_KEY));
    }

    /**
     * Test that password reset fails without valid Turnstile response.
     */
    @Test
    public void testPasswordResetFailsWithoutTurnstileResponse() {
        configureResetCredentialsFlowWithTurnstile();

        loginPage.open();
        loginPage.resetPassword();
        resetPasswordPage.assertCurrent();

        // Try to reset password without Turnstile response
        resetPasswordPage.changePassword("test-user@localhost");

        resetPasswordPage.assertCurrent();
        String pageSource = driver.getPageSource();
        assertThat("Should show Turnstile error", pageSource,
            containsString("Invalid Turnstile verification"));
    }

    /**
     * Test that Turnstile theme configuration is applied.
     */
    @Test
    public void testTurnstileThemeConfiguration() {
        Map<String, String> config = createTurnstileConfig();
        config.put(TurnstileHelper.THEME, "dark");
        config.put(TurnstileHelper.SIZE, "compact");
        config.put(TurnstileHelper.ACTION, "custom_register");

        String flowAlias = "RegistrationWithCustomTurnstile";
        FlowUtil.injectExecutionWithConfig(
            testRealm(),
            DefaultAuthenticationFlows.REGISTRATION_FLOW,
            flowAlias,
            RegistrationTurnstile.PROVIDER_ID,
            config,
            AuthenticationExecutionModel.Requirement.REQUIRED
        );

        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setRegistrationFlow(flowAlias);
        testRealm().update(realm);

        loginPage.open();
        loginPage.clickRegister();
        registerPage.assertCurrent();

        String pageSource = driver.getPageSource();
        assertThat("Theme should be set to dark", pageSource, 
            containsString("data-theme=\"dark\""));
        assertThat("Size should be set to compact", pageSource, 
            containsString("data-size=\"compact\""));
        assertThat("Action should be custom_register", pageSource, 
            containsString("data-action=\"custom_register\""));
    }

    /**
     * Test that invalid action names are rejected and fall back to defaults.
     */
    @Test
    public void testInvalidActionNameFallback() {
        Map<String, String> config = createTurnstileConfig();
        config.put(TurnstileHelper.ACTION, "invalid-action-name!");

        String flowAlias = "RegistrationWithInvalidAction";
        FlowUtil.injectExecutionWithConfig(
            testRealm(),
            DefaultAuthenticationFlows.REGISTRATION_FLOW,
            flowAlias,
            RegistrationTurnstile.PROVIDER_ID,
            config,
            AuthenticationExecutionModel.Requirement.REQUIRED
        );

        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setRegistrationFlow(flowAlias);
        testRealm().update(realm);

        loginPage.open();
        loginPage.clickRegister();
        registerPage.assertCurrent();

        String pageSource = driver.getPageSource();
        // Should fall back to default action name
        assertThat("Should use default action", pageSource, 
            containsString("data-action=\"register\""));
    }

    /**
     * Test that Turnstile can be disabled without breaking flows.
     */
    @Test
    public void testTurnstileDisabled() {
        String flowAlias = "RegistrationWithDisabledTurnstile";
        FlowUtil.injectExecutionWithConfig(
            testRealm(),
            DefaultAuthenticationFlows.REGISTRATION_FLOW,
            flowAlias,
            RegistrationTurnstile.PROVIDER_ID,
            createTurnstileConfig(),
            AuthenticationExecutionModel.Requirement.DISABLED
        );

        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setRegistrationFlow(flowAlias);
        testRealm().update(realm);

        loginPage.open();
        loginPage.clickRegister();
        registerPage.assertCurrent();

        // Verify Turnstile widget is NOT present
        String pageSource = driver.getPageSource();
        Assert.assertFalse("Turnstile widget should not be present",
            pageSource.contains("cf-turnstile"));

        // Registration should work without Turnstile
        registerPage.register("firstName", "lastName", "test@test.com",
            "test-user", "password", "password");

        appPage.assertCurrent();
    }

    // Helper methods

    private void configureRegistrationFlowWithTurnstile() {
        String flowAlias = "RegistrationWithTurnstile";
        FlowUtil.injectExecutionWithConfig(
            testRealm(),
            DefaultAuthenticationFlows.REGISTRATION_FLOW,
            flowAlias,
            RegistrationTurnstile.PROVIDER_ID,
            createTurnstileConfig(),
            AuthenticationExecutionModel.Requirement.REQUIRED
        );

        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setRegistrationFlow(flowAlias);
        testRealm().update(realm);
    }

    private void configureBrowserFlowWithTurnstile() {
        String flowAlias = "BrowserWithTurnstile";
        
        // Create a copy of the browser flow
        AuthenticationFlowRepresentation browserFlow = testRealm().flows()
            .getFlows()
            .stream()
            .filter(f -> f.getAlias().equals(DefaultAuthenticationFlows.BROWSER_FLOW))
            .findFirst()
            .orElseThrow();

        AuthenticationFlowRepresentation newFlow = new AuthenticationFlowRepresentation();
        newFlow.setAlias(flowAlias);
        newFlow.setDescription("Browser flow with Turnstile");
        newFlow.setProviderId("basic-flow");
        newFlow.setTopLevel(true);
        newFlow.setBuiltIn(false);

        Response response = testRealm().flows().createFlow(newFlow);
        response.close();

        // Add Username Password Form with Turnstile execution
        Map<String, String> data = new HashMap<>();
        data.put("provider", UsernamePasswordFormWithTurnstileFactory.PROVIDER_ID);
        testRealm().flows().addExecution(flowAlias, data);

        // Get the execution and configure it
        List<AuthenticationExecutionInfoRepresentation> executions = 
            testRealm().flows().getExecutions(flowAlias);
        AuthenticationExecutionInfoRepresentation execution = executions.stream()
            .filter(e -> e.getProviderId().equals(UsernamePasswordFormWithTurnstileFactory.PROVIDER_ID))
            .findFirst()
            .orElseThrow();

        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED.name());
        testRealm().flows().updateExecutions(flowAlias, execution);

        // Configure Turnstile
        AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
        config.setAlias("turnstile-browser");
        config.setConfig(createTurnstileConfig());
        response = testRealm().flows().newExecutionConfig(execution.getId(), config);
        response.close();

        // Set as browser flow
        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setBrowserFlow(flowAlias);
        testRealm().update(realm);
    }

    private void configureResetCredentialsFlowWithTurnstile() {
        String flowAlias = "ResetWithTurnstile";
        
        // Create a copy of the reset credentials flow
        AuthenticationFlowRepresentation newFlow = new AuthenticationFlowRepresentation();
        newFlow.setAlias(flowAlias);
        newFlow.setDescription("Reset credentials flow with Turnstile");
        newFlow.setProviderId("basic-flow");
        newFlow.setTopLevel(true);
        newFlow.setBuiltIn(false);

        Response response = testRealm().flows().createFlow(newFlow);
        response.close();

        // Add Choose User with Turnstile execution
        Map<String, String> data = new HashMap<>();
        data.put("provider", ResetCredentialChooseUserWithTurnstileFactory.PROVIDER_ID);
        testRealm().flows().addExecution(flowAlias, data);

        // Get the execution and configure it
        List<AuthenticationExecutionInfoRepresentation> executions = 
            testRealm().flows().getExecutions(flowAlias);
        AuthenticationExecutionInfoRepresentation execution = executions.stream()
            .filter(e -> e.getProviderId().equals(ResetCredentialChooseUserWithTurnstileFactory.PROVIDER_ID))
            .findFirst()
            .orElseThrow();

        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED.name());
        testRealm().flows().updateExecutions(flowAlias, execution);

        // Configure Turnstile
        AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
        config.setAlias("turnstile-reset");
        config.setConfig(createTurnstileConfig());
        response = testRealm().flows().newExecutionConfig(execution.getId(), config);
        response.close();

        // Set as reset credentials flow
        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setResetCredentialsFlow(flowAlias);
        testRealm().update(realm);
    }

    private Map<String, String> createTurnstileConfig() {
        Map<String, String> config = new HashMap<>();
        config.put(TurnstileHelper.SITE_KEY, TEST_SITE_KEY);
        config.put(TurnstileHelper.SECRET_KEY, TEST_SECRET_KEY);
        config.put(TurnstileHelper.ACTION, "register");
        config.put(TurnstileHelper.THEME, "auto");
        config.put(TurnstileHelper.SIZE, "normal");
        return config;
    }

    private Map<String, String> createTurnstileConfigWithoutSecretKey() {
        Map<String, String> config = new HashMap<>();
        config.put(TurnstileHelper.SITE_KEY, TEST_SITE_KEY);
        // SECRET_KEY intentionally omitted for testing missing secret key scenario
        return config;
    }
}
