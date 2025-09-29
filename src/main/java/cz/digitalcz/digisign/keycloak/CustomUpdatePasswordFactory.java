package cz.digitalcz.digisign.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomUpdatePasswordFactory implements RequiredActionFactory {

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new CustomUpdatePassword();
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