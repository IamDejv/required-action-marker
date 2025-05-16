package cz.digitalcz.digisign.keycloak;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.UpdateTotp;

public class CustomUpdateTotp extends UpdateTotp {
    public static final String NOTE_KEY = "CONFIGURE_TOTP";

    @Override
    public void processAction(RequiredActionContext context) {
        super.processAction(context);
        if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
            context.getAuthenticationSession().setAuthNote(NOTE_KEY, getId());
        }
    }

    @Override
    public String getDisplayText() {
        return "Custom Configure OTP";
    }

    @Override
    public String getId() {
        return "CONFIGURE_TOTP";
    }
}
