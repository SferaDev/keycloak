import {
  ActionGroup,
  Button,
  FormGroup,
  PageSection,
  TextArea,
  TextInput,
} from "@patternfly/react-core";
import { FormProvider, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router-dom";
import { useAdminClient } from "../admin-client";
import { useAlerts } from "@keycloak/keycloak-ui-shared";
import { FormAccess } from "../components/form/FormAccess";
import { ViewHeader } from "../components/view-header/ViewHeader";
import { useRealm } from "../context/realm-context/RealmContext";
import { useParams } from "../utils/useParams";
import type { EditOrganizationParams } from "./routes/EditOrganization";
import type RoleRepresentation from "@keycloak/keycloak-admin-client/lib/defs/roleRepresentation";

type OrganizationRoleForm = {
  name: string;
  description?: string;
};

export default function CreateOrganizationRole() {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const { realm } = useRealm();
  const { id: organizationId } = useParams<EditOrganizationParams>();
  const navigate = useNavigate();

  const form = useForm<OrganizationRoleForm>({
    mode: "onChange",
  });

  const save = async (formValues: OrganizationRoleForm) => {
    try {
      const role: RoleRepresentation = {
        name: formValues.name,
        description: formValues.description,
      };

      await adminClient.organizations.roles.create(
        { id: organizationId },
        role
      );
      
      addAlert(t("roleCreatedSuccess"));
      navigate(`/${realm}/organizations/${organizationId}/roles`);
    } catch (error) {
      addError("roleCreationError", error);
    }
  };

  return (
    <>
      <ViewHeader
        titleKey="createRole"
        subKey="createRoleSubText"
      />
      <PageSection variant="light">
        <FormProvider {...form}>
          <FormAccess
            isHorizontal
            role="manage-users"
            onSubmit={form.handleSubmit(save)}
          >
            <FormGroup
              label={t("name")}
              fieldId="name"
              isRequired
              validated={form.formState.errors.name ? "error" : "default"}
              helperTextInvalid={form.formState.errors.name?.message}
            >
              <TextInput
                id="name"
                data-testid="role-name"
                validated={form.formState.errors.name ? "error" : "default"}
                {...form.register("name", {
                  required: t("required"),
                  pattern: {
                    value: /^[a-zA-Z0-9_-]+$/,
                    message: t("invalidRoleName"),
                  },
                })}
              />
            </FormGroup>

            <FormGroup
              label={t("description")}
              fieldId="description"
              validated={form.formState.errors.description ? "error" : "default"}
              helperTextInvalid={form.formState.errors.description?.message}
            >
              <TextArea
                id="description"
                data-testid="role-description"
                validated={form.formState.errors.description ? "error" : "default"}
                {...form.register("description")}
              />
            </FormGroup>

            <ActionGroup>
              <Button
                variant="primary"
                type="submit"
                data-testid="save"
                isDisabled={!form.formState.isValid}
              >
                {t("create")}
              </Button>
              <Button
                variant="link"
                component={(props) => (
                  <Link
                    {...props}
                    to={`/${realm}/organizations/${organizationId}/roles`}
                  />
                )}
              >
                {t("cancel")}
              </Button>
            </ActionGroup>
          </FormAccess>
        </FormProvider>
      </PageSection>
    </>
  );
}