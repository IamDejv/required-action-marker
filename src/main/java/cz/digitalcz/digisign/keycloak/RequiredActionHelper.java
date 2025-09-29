package cz.digitalcz.digisign.keycloak;

import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.models.UserModel;

public class RequiredActionHelper {

    /**
     * Zkusí detekovat dokončenou required action různými způsoby
     */
    public static String detectCompletedAction(AuthenticationSessionModel authSession, UserModel user) {
        if (authSession == null) {
            return null;
        }

        // 1. Zkusit načíst z auth note (hlavní způsob)
        String actionFromNote = authSession.getAuthNote(CustomLoginFormsProvider.REQUIRED_ACTION_UPDATED_NOTE_KEY);
        if (actionFromNote != null) {
            return actionFromNote;
        }

        // 2. Zkusit z client note
        String actionFromClient = authSession.getClientNote(CustomLoginFormsProvider.REQUIRED_ACTION_UPDATED_NOTE_KEY);
        if (actionFromClient != null) {
            return actionFromClient;
        }

        // 3. Zkusit z user note (pokud máme user)
        if (user != null) {
            String actionFromUser = user.getFirstAttribute("lastCompletedRequiredAction");
            if (actionFromUser != null) {
                return actionFromUser;
            }
        }

        return null;
    }

    /**
     * Nastaví dokončenou action více způsoby pro větší spolehlivost
     */
    public static void markActionCompleted(AuthenticationSessionModel authSession, UserModel user, String actionId) {
        if (authSession != null) {
            // Hlavní způsob - auth note
            authSession.setAuthNote(CustomLoginFormsProvider.REQUIRED_ACTION_UPDATED_NOTE_KEY, actionId);

            // Záložní způsob - client note
            authSession.setClientNote(CustomLoginFormsProvider.REQUIRED_ACTION_UPDATED_NOTE_KEY, actionId);

        }

        // Dlouhodobé uložení do user attributes
        if (user != null) {
            user.setSingleAttribute("lastCompletedRequiredAction", actionId);
            user.setSingleAttribute("lastCompletedRequiredActionTime", String.valueOf(System.currentTimeMillis()));
        }
    }
}