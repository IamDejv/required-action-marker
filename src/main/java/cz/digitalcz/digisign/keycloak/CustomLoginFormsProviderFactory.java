package cz.digitalcz.digisign.keycloak;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.LoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomLoginFormsProviderFactory implements LoginFormsProviderFactory {
    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new CustomLoginFormsProvider(session);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return "freemarker";
    }
}
