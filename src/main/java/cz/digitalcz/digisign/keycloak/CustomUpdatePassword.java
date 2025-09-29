package cz.digitalcz.digisign.keycloak;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.UpdatePassword;

public class CustomUpdatePassword extends UpdatePassword {
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
    public String getDisplayText() {
        return "Custom Update Password";
    }

    @Override
    public String getId() {
        return "UPDATE_PASSWORD";
    }
}
