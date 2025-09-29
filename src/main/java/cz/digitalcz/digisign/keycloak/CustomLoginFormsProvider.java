package cz.digitalcz.digisign.keycloak;

import java.util.Properties;
import java.util.Locale;

import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.forms.login.LoginFormsPages;

public class CustomLoginFormsProvider extends FreeMarkerLoginFormsProvider {
    public static final String REQUIRED_ACTION_UPDATED_NOTE_KEY = "requiredActionUpdated";


    public CustomLoginFormsProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    protected void createCommonAttributes(Theme theme, Locale locale, Properties messagesBundle, UriBuilder baseUriBuilder, LoginFormsPages page) {
        super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);

        AuthenticationSessionModel authSession = this.authenticationSession;
        String requiredActionUpdated = RequiredActionHelper.detectCompletedAction(authSession, this.user);

        if (requiredActionUpdated != null) {
            setAttribute("requiredActionUpdated", requiredActionUpdated);
            setAttribute("hasRequiredActionUpdated", true);
        } else {
            setAttribute("hasRequiredActionUpdated", false);
        }
    }
}
