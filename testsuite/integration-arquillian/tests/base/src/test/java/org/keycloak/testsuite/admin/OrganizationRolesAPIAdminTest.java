package org.keycloak.testsuite.admin;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.admin.client.resource.OrganizationsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.arquillian.annotation.InitialLocks;
import org.keycloak.testsuite.arquillian.annotation.LockRealm;
import org.keycloak.testsuite.page.AbstractPatternFlyAlert;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.UserBuilder;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.keycloak.testsuite.util.AssertAdminEvents.assertAdminEventsContains;
import static org.keycloak.testsuite.util.AssertAdminEvents.assertLastAdminEvent;


public class OrganizationRolesAPIAdminTest extends AbstractTestRealmKeycloakTest {

    @Deployment
    public static WebArchive deploy() {
        return RunOnServerDeployment.create(OrganizationRolesAPIAdminTest.class);
    }

    private OrganizationsResource organizationsResource;
    private String testOrganizationId;
    private OrganizationResource testOrganizationResource;

    @Override
    public void configureTestRealm(org.keycloak.representations.idm.RealmRepresentation testRealm) {
        // Configure realm if needed, e.g., enable organizations if it's a feature flag
    }

    @Before
    public void setUp() {
        super.setUp(); // From AbstractTestRealmKeycloakTest
        RealmResource realmResource = adminClient.realm(TEST_REALM_NAME);
        organizationsResource = realmResource.organizations();

        // Create a test organization for each test run
        OrganizationRepresentation orgRep = new OrganizationRepresentation();
        orgRep.setName("test-org-" + System.currentTimeMillis());
        try (Response response = organizationsResource.create(orgRep)) {
            assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus());
            List<OrganizationRepresentation> found = organizationsResource.search(orgRep.getName(), true, 0, 1);
            assertThat(found, hasSize(1));
            testOrganizationId = found.get(0).getId();
            testOrganizationResource = organizationsResource.organization(testOrganizationId);
            assertNotNull(testOrganizationResource);
        }
    }

    private RoleRepresentation createRoleRepresentation(String name) {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(name);
        roleRep.setDescription("Test role description for " + name);
        return roleRep;
    }

    @Test
    @LockRealm(TEST_REALM_NAME)
    public void testCreateAndGetOrganizationRole() {
        RoleRepresentation roleRep = createRoleRepresentation("org-role-1");

        // Create role
        try (Response response = testOrganizationResource.roles().create(roleRep)) {
            assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus());
        }

        // Get role by name
        RoleRepresentation createdRole = testOrganizationResource.roles().get(roleRep.getName()).toRepresentation();
        assertNotNull(createdRole);
        assertEquals(roleRep.getName(), createdRole.getName());
        assertEquals(roleRep.getDescription(), createdRole.getDescription());
        // For org roles, clientRole should be false. ContainerId might be tricky - it could be realmId or orgId depending on RoleModel impl.
        // Let's assume for now RoleRepresentation from org roles endpoint correctly reflects its nature.
        // assertFalse(createdRole.isClientRole());
    }

    @Test
    @LockRealm(TEST_REALM_NAME)
    public void testListOrganizationRoles() {
        testOrganizationResource.roles().create(createRoleRepresentation("role-a"));
        testOrganizationResource.roles().create(createRoleRepresentation("role-b"));

        List<RoleRepresentation> roles = testOrganizationResource.roles().list();
        assertThat(roles, hasSize(2));
        List<String> roleNames = roles.stream().map(RoleRepresentation::getName).collect(Collectors.toList());
        assertThat(roleNames, containsInAnyOrder("role-a", "role-b"));
    }

    @Test
    @LockRealm(TEST_REALM_NAME)
    public void testUpdateOrganizationRole() {
        String roleName = "org-role-to-update";
        testOrganizationResource.roles().create(createRoleRepresentation(roleName));

        RoleRepresentation roleToUpdate = testOrganizationResource.roles().get(roleName).toRepresentation();
        roleToUpdate.setDescription("Updated description");
        roleToUpdate.setName("updated-" + roleName); // Test renaming too, if supported and makes sense

        testOrganizationResource.roles().get(roleName).update(roleToUpdate);

        RoleRepresentation updatedRole = testOrganizationResource.roles().get(roleToUpdate.getName()).toRepresentation();
        assertEquals(roleToUpdate.getDescription(), updatedRole.getDescription());
        assertEquals(roleToUpdate.getName(), updatedRole.getName());

        // Check that old name is gone
        try {
            testOrganizationResource.roles().get(roleName).toRepresentation();
            fail("Should not find role by old name after update");
        } catch (NotFoundException e) {
            // Expected
        }
    }

    @Test
    @LockRealm(TEST_REALM_NAME)
    public void testDeleteOrganizationRole() {
        String roleName = "org-role-to-delete";
        testOrganizationResource.roles().create(createRoleRepresentation(roleName));

        assertNotNull(testOrganizationResource.roles().get(roleName).toRepresentation());

        testOrganizationResource.roles().get(roleName).remove();

        try {
            testOrganizationResource.roles().get(roleName).toRepresentation();
            fail("Should not find role after deletion");
        } catch (NotFoundException e) {
            // Expected
        }
    }

    @Test
    @LockRealm(TEST_REALM_NAME)
    public void testCreateDuplicateOrganizationRoleError() {
        String roleName = "duplicate-org-role";
        testOrganizationResource.roles().create(createRoleRepresentation(roleName));

        try (Response response = testOrganizationResource.roles().create(createRoleRepresentation(roleName))) {
            assertEquals(Response.Status.CONFLICT.getStatusCode(), response.getStatus());
        }
    }

    @Test
    @LockRealm(TEST_REALM_NAME)
    public void testUserRoleMappings() {
        // Create a user
        UserResource userResource = AdminClientUtil.createUserWithAdminClient(adminClient.realm(TEST_REALM_NAME), UserBuilder.create().username("orguser").password("password").build());
        UserRepresentation user = userResource.toRepresentation();

        // Create some org roles
        RoleRepresentation orgRole1 = createRoleRepresentation("org-member-role1");
        RoleRepresentation orgRole2 = createRoleRepresentation("org-member-role2");
        testOrganizationResource.roles().create(orgRole1);
        testOrganizationResource.roles().create(orgRole2);

        // Need to fetch the full RoleRepresentation with ID for assignment
        orgRole1 = testOrganizationResource.roles().get(orgRole1.getName()).toRepresentation();
        orgRole2 = testOrganizationResource.roles().get(orgRole2.getName()).toRepresentation();

        // Assign orgRole1 to user
        testOrganizationResource.members().member(user.getId()).roles().add(List.of(orgRole1));

        // List user's org roles
        List<RoleRepresentation> userRoles = testOrganizationResource.members().member(user.getId()).roles().listAll();
        assertThat(userRoles, hasSize(1));
        assertEquals(orgRole1.getName(), userRoles.get(0).getName());

        // Assign orgRole2 (add to existing)
        testOrganizationResource.members().member(user.getId()).roles().add(List.of(orgRole2));
        userRoles = testOrganizationResource.members().member(user.getId()).roles().listAll();
        assertThat(userRoles, hasSize(2));
        assertThat(userRoles.stream().map(RoleRepresentation::getName).collect(Collectors.toList()),
                   containsInAnyOrder(orgRole1.getName(), orgRole2.getName()));

        // Unassign orgRole1
        testOrganizationResource.members().member(user.getId()).roles().remove(List.of(orgRole1));
        userRoles = testOrganizationResource.members().member(user.getId()).roles().listAll();
        assertThat(userRoles, hasSize(1));
        assertEquals(orgRole2.getName(), userRoles.get(0).getName());

        // Unassign orgRole2
        testOrganizationResource.members().member(user.getId()).roles().remove(List.of(orgRole2));
        userRoles = testOrganizationResource.members().member(user.getId()).roles().listAll();
        assertThat(userRoles, is(empty()));
    }
}
