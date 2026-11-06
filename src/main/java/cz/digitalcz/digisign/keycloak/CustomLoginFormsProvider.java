package cz.digitalcz.digisign.keycloak;

import java.util.Map;
import java.util.Properties;
import java.util.Locale;

import org.keycloak.common.util.Time;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.forms.login.LoginFormsPages;

public class CustomLoginFormsProvider extends FreeMarkerLoginFormsProvider {
    public static final String REQUIRED_ACTION_UPDATED_NOTE_KEY = "requiredActionUpdated";
    public static final String DIGISIGN_PARAMS_ATTRIBUTE = "digisignParams";
    private static final String DIGISIGN_PARAMS_APPLIED_NOTE = "digisign_params_applied";

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

        if (authSession != null) {
            applyDigisignParams(authSession);
        }
    }

    /**
     * Exposes the params sealed by the DigiSign APP to the theme as {@code digisignParams} and hands their
     * {@code kc_action} to Keycloak the same way a plain {@code kc_action} request parameter would.
     */
    private void applyDigisignParams(AuthenticationSessionModel authSession) {
        String token = authSession.getClientNote(DigisignParams.CLIENT_NOTE);

        if (token == null) {
            return;
        }

        ClientModel client = authSession.getClient();
        Map<String, Object> params = DigisignParams.unseal(token, client.getSecret(), client.getClientId(), Time.currentTime());

        if (params == null) {
            return;
        }

        setAttribute(DIGISIGN_PARAMS_ATTRIBUTE, params);

        // every rendered page passes here, the required action page included — re-arming it would loop
        if (authSession.getAuthNote(DIGISIGN_PARAMS_APPLIED_NOTE) != null) {
            return;
        }

        authSession.setAuthNote(DIGISIGN_PARAMS_APPLIED_NOTE, "1");

        if (params.get("kc_action") instanceof String action) {
            RequiredActionProviderModel requiredAction = authSession.getRealm().getRequiredActionProviderByAlias(action);

            if (requiredAction != null && requiredAction.isEnabled()) {
                authSession.setClientNote(Constants.KC_ACTION, action);
            }
        }
    }
}
