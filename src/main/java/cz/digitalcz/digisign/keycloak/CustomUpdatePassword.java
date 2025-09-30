package cz.digitalcz.digisign.keycloak;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.UpdatePassword;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.OTPCredentialModel;
import jakarta.ws.rs.core.MultivaluedMap;

public class CustomUpdatePassword extends UpdatePassword {

    private final OTPCheck otpCheck = new OTPCheck();

    public CustomUpdatePassword(KeycloakSession session) {
        super(session);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        boolean hasOTP = context.getUser()
            .credentialManager()
            .isConfiguredFor(OTPCredentialModel.TYPE);

        if (hasOTP) {
            otpCheck.requiredActionChallenge(context);
        } else {
            super.requiredActionChallenge(context);
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        // Zkontroluj, jestli se jedná o OTP submission
        String otpCode = formData.getFirst("otp");
        boolean hasOTP = context.getUser()
            .credentialManager()
            .isConfiguredFor(OTPCredentialModel.TYPE);

        if (hasOTP && otpCode != null && !otpCode.trim().isEmpty()) {
            // Zpracuj OTP pomocí OTP PreCheck
            otpCheck.processAction(context);

            if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
                // OTP bylo úspěšně ověřeno → zobraz password form
                super.requiredActionChallenge(context);
            }
        } else {
            super.processAction(context);
            if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
                RequiredActionHelper.markActionCompleted(
                    context.getAuthenticationSession(),
                    context.getUser(),
                    getId()
                );
            }
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
