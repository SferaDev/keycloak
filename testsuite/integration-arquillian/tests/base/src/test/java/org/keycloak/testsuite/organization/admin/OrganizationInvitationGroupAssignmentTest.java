/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.organization.admin;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MemberRepresentation;
import org.keycloak.representations.idm.MembershipType;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.pages.InfoPage;
import org.keycloak.testsuite.pages.RegisterPage;
import org.keycloak.testsuite.util.GreenMailRule;
import org.keycloak.testsuite.util.MailUtils;
import org.keycloak.testsuite.util.MailUtils.EmailBody;
import org.keycloak.testsuite.util.UserBuilder;

import org.hamcrest.Matchers;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

public class OrganizationInvitationGroupAssignmentTest extends AbstractOrganizationTest {

    @Rule
    public GreenMailRule greenMail = new GreenMailRule();

    @Page
    protected InfoPage infoPage;

    @Page
    protected RegisterPage registerPage;

    @Before
    public void setDriverTimeout() {
        driver.manage().timeouts().pageLoadTimeout(Duration.ofMinutes(1));
    }

    @Before
    public void disableSelfRegistration() {
        RealmRepresentation representation = testRealm().toRepresentation();
        representation.setRegistrationAllowed(false);
        testRealm().update(representation);
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        super.configureTestRealm(testRealm);
        testRealm.setRegistrationAllowed(false);
    }

    @Test
    public void testInviteExistingUserWithGroups() throws IOException, MessagingException {
        UserRepresentation user = createUser("invited", "invited@myemail.com");
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        String groupId = createTopLevelGroup(organization, "engineering");

        try (Response response = organization.members().inviteExistingUser(user.getId(), List.of(groupId))) {
            assertThat(response.getStatus(), equalTo(Response.Status.NO_CONTENT.getStatusCode()));
        }

        acceptInvitation(organization, user);

        // Verify user is in the specified group
        List<GroupRepresentation> memberGroups = organization.members().member(user.getId()).groups(null, null, false);
        assertThat(memberGroups, Matchers.hasSize(1));
        assertThat(memberGroups.get(0).getId(), equalTo(groupId));
    }

    @Test
    public void testInviteUserByEmailWithGroups() throws IOException, MessagingException {
        UserRepresentation user = createUser("invited", "invited@myemail.com");
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        String groupId1 = createTopLevelGroup(organization, "engineering");
        String groupId2 = createTopLevelGroup(organization, "marketing");

        try (Response response = organization.members().inviteUser(user.getEmail(), "Homer", "Simpson", List.of(groupId1, groupId2))) {
            assertThat(response.getStatus(), equalTo(Response.Status.NO_CONTENT.getStatusCode()));
        }

        acceptInvitation(organization, user);

        // Verify user is in both groups
        List<GroupRepresentation> memberGroups = organization.members().member(user.getId()).groups(null, null, false);
        assertThat(memberGroups, Matchers.hasSize(2));
        List<String> groupIds = memberGroups.stream().map(GroupRepresentation::getId).toList();
        assertThat(groupIds, Matchers.containsInAnyOrder(groupId1, groupId2));
    }

    @Test
    public void testInviteNewUserRegistrationWithGroups() throws IOException, MessagingException {
        String email = "inviteduser@email";
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        String groupId = createTopLevelGroup(organization, "engineering");

        organization.members().inviteUser(email, "Homer", "Simpson", List.of(groupId)).close();

        registerUser(organization, email);

        List<UserRepresentation> users = testRealm().users().searchByEmail(email, true);
        assertThat(users, not(empty()));
        MemberRepresentation member = organization.members().member(users.get(0).getId()).toRepresentation();
        Assertions.assertNotNull(member);
        assertThat(member.getMembershipType(), equalTo(MembershipType.MANAGED));
        getCleanup().addCleanup(() -> testRealm().users().get(users.get(0).getId()).remove());

        // Verify user is in the specified group
        List<GroupRepresentation> memberGroups = organization.members().member(users.get(0).getId()).groups(null, null, false);
        assertThat(memberGroups, Matchers.hasSize(1));
        assertThat(memberGroups.get(0).getId(), equalTo(groupId));
    }

    @Test
    public void testInviteWithInvalidGroupIdRejected() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        String fakeGroupId = UUID.randomUUID().toString();

        try (Response response = organization.members().inviteUser("test@email.com", "Test", "User", List.of(fakeGroupId))) {
            assertThat(response.getStatus(), equalTo(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void testInviteWithGroupFromDifferentOrgRejected() {
        OrganizationResource org1 = testRealm().organizations().get(createOrganization("org1").getId());
        OrganizationResource org2 = testRealm().organizations().get(createOrganization("org2").getId());

        String groupInOrg2 = createTopLevelGroup(org2, "eng");

        // Trying to invite with a group from org2 should fail for org1
        try (Response response = org1.members().inviteUser("test@email.com", "Test", "User", List.of(groupInOrg2))) {
            assertThat(response.getStatus(), equalTo(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void testInviteWithoutGroupsUnchanged() throws IOException, MessagingException {
        UserRepresentation user = createUser("invited", "invited@myemail.com");
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        // Invite without groups (backward compatibility)
        try (Response response = organization.members().inviteExistingUser(user.getId())) {
            assertThat(response.getStatus(), equalTo(Response.Status.NO_CONTENT.getStatusCode()));
        }

        acceptInvitation(organization, user);

        // Verify user is a member but not in any org groups
        Assertions.assertNotNull(organization.members().member(user.getId()).toRepresentation());
        List<GroupRepresentation> memberGroups = organization.members().member(user.getId()).groups(null, null, false);
        assertThat(memberGroups, empty());
    }

    @Test
    public void testInviteExistingUserWithGroupsByEmail() throws IOException, MessagingException {
        UserRepresentation user = createUser("invited", "invited@myemail.com");
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        String groupId = createTopLevelGroup(organization, "engineering");

        try (Response response = organization.members().inviteUser(user.getEmail(), null, null, List.of(groupId))) {
            assertThat(response.getStatus(), equalTo(Response.Status.NO_CONTENT.getStatusCode()));
        }

        acceptInvitation(organization, user);

        List<GroupRepresentation> memberGroups = organization.members().member(user.getId()).groups(null, null, false);
        assertThat(memberGroups, Matchers.hasSize(1));
        assertThat(memberGroups.get(0).getId(), equalTo(groupId));
    }

    private UserRepresentation createUser(String username, String email) {
        UserRepresentation user = UserBuilder.create()
                .username(username)
                .email(email)
                .password("password")
                .enabled(true)
                .build();
        try (Response response = testRealm().users().create(user)) {
            user.setId(ApiUtil.getCreatedId(response));
        }
        getCleanup().addUserId(user.getId());
        return user;
    }

    private String createTopLevelGroup(OrganizationResource organization, String name) {
        GroupRepresentation group = new GroupRepresentation();
        group.setName(name);
        try (Response response = organization.groups().addTopLevelGroup(group)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            return ApiUtil.getCreatedId(response);
        }
    }

    private String getInvitationLinkFromEmail() throws MessagingException, IOException {
        MimeMessage message = greenMail.getLastReceivedMessage();
        Assertions.assertNotNull(message);
        EmailBody body = MailUtils.getBody(message);
        return MailUtils.getLink(body.getHtml()).trim();
    }

    private void registerUser(OrganizationResource organization, String email) throws MessagingException, IOException {
        String link = getInvitationLinkFromEmail();
        driver.navigate().to(link);
        Assertions.assertFalse(organization.members().list(-1, -1).stream().anyMatch(actual -> email.equals(actual.getEmail())));
        registerPage.assertCurrent(organizationName);
        assertThat(registerPage.getEmail(), equalTo(email));
        registerPage.register("firstName", "lastName", email,
                "invitedUser", "password", "password", null, false, null);
    }

    private void acceptInvitation(OrganizationResource organization, UserRepresentation user) throws MessagingException, IOException {
        String link = getInvitationLinkFromEmail();
        driver.navigate().to(link);
        // not yet a member
        Assertions.assertFalse(organization.members().list(-1, -1).stream().anyMatch(actual -> user.getId().equals(actual.getId())));
        // confirm the intent of membership
        assertThat(driver.getPageSource(), containsString("You are about to join organization"));
        infoPage.clickToContinue();
        // now a member
        Assertions.assertNotNull(organization.members().member(user.getId()).toRepresentation());
    }
}
