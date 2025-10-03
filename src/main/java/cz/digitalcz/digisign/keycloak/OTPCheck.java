package cz.digitalcz.digisign.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class OTPCheck implements RequiredActionProvider, RequiredActionFactory {

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        // No automatic triggers - only runs when explicitly required
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        boolean hasOTP = context.getUser()
            .credentialManager()
            .isConfiguredFor(OTPCredentialModel.TYPE);

        if (!hasOTP) {
            context.success();
            RequiredActionHelper.markActionCompleted(
                context.getAuthenticationSession(),
                context.getUser(),
                getId()
            );
            return;
        }

        Response challenge = context.form()
            .setAttribute("otpRequired", true)
            .createForm("login-otp.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String otpCode = formData.getFirst("otp");

        if (otpCode == null || otpCode.trim().isEmpty()) {
            Response challenge = context.form()
                .setAttribute("otpRequired", true)
                .setError("missingTotpMessage")
                .createForm("login-otp.ftl");
            context.challenge(challenge);
            return;
        }

        UserModel user = context.getUser();
        boolean isValid = false;

        try {
            var credentials = user.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).toList();

            if (!credentials.isEmpty()) {
                var credential = credentials.get(0);
                String credentialId = credential.getId();

                OTPCredentialProvider otpProvider = (OTPCredentialProvider) context.getSession()
                    .getProvider(CredentialProvider.class, "keycloak-otp");

                if (otpProvider != null) {
                    UserCredentialModel otpCredential = new UserCredentialModel(
                        credentialId,
                        otpProvider.getType(),
                        otpCode
                    );

                    isValid = user.credentialManager().isValid(otpCredential);
                }
            }

        } catch (Exception e) {
            isValid = false;
        }

        if (isValid) {
            context.success();
            RequiredActionHelper.markActionCompleted(
                context.getAuthenticationSession(),
                context.getUser(),
                getId()
            );
        } else {
            Response challenge = context.form()
                .setAttribute("otpRequired", true)
                .setError("invalidTotpMessage")
                .createForm("login-otp.ftl");
            context.challenge(challenge);
        }
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new OTPCheck();
    }

    @Override
    public String getId() {
        return "OTP_CHECK";
    }

    @Override
    public String getDisplayText() {
        return "OTP Check";
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