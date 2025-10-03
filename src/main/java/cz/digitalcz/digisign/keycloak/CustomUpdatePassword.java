package cz.digitalcz.digisign.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.UpdatePassword;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomUpdatePassword extends UpdatePassword {

    public CustomUpdatePassword() {
        super();
    }

    public CustomUpdatePassword(KeycloakSession session) {
        super(session);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        super.requiredActionChallenge(context);
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
        return new CustomUpdatePassword(session);
    }

    @Override
    public String getId() {
        return "UPDATE_PASSWORD";
    }

    @Override
    public String getDisplayText() {
        return "Custom Update Password";
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
        return true;
    }
}
