package cz.digitalcz.digisign.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.UpdateTotp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomUpdateTotp extends UpdateTotp {

    public CustomUpdateTotp() {
        super();
    }

    @Override
    public void processAction(RequiredActionContext context) {
        super.processAction(context);
        if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
            RequiredActionHelper.markActionCompleted(
                context.getAuthenticationSession(),
                context.getUser(),
                getId()
            );
        }
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new CustomUpdateTotp();
    }

    @Override
    public String getId() {
        return "CONFIGURE_TOTP";
    }

    @Override
    public String getDisplayText() {
        return "Custom Configure OTP";
    }

    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }

    @Override
    public boolean isOneTimeAction() {
        return false;
    }
}
