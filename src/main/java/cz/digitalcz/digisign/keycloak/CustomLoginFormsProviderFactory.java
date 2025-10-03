package cz.digitalcz.digisign.keycloak;

import org.keycloak.Config;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomLoginFormsProviderFactory extends FreeMarkerLoginFormsProviderFactory {

    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new CustomLoginFormsProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        super.postInit(factory);
    }

    @Override
    public void close() {
        super.close();
    }

    @Override
    public String getId() {
        return "freemarker";
    }
}
