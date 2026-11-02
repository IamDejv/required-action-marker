package cz.digitalcz.digisign.keycloak;

import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.models.UserModel;

public class RequiredActionHelper {

    private static final String LAST_COMPLETED_ACTION_ATTR = "lastCompletedRequiredAction";
    private static final String LAST_COMPLETED_ACTION_TIME_ATTR = "lastCompletedRequiredActionTime";

    /**
     * Jak dlouho po dokončení akce považujeme fallback z user attributes za platný.
     * Bez tohoto okna by se potvrzovací obrazovka zobrazovala i na pozdějších
     * (nesouvisejících) info stránkách, protože atribut se nikdy nemaže.
     */
    private static final long COMPLETED_ACTION_TTL_MS = 60_000L;

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

        // 3. Fallback z user attributes - platí jen krátce po dokončení akce
        if (user != null) {
            String actionFromUser = user.getFirstAttribute(LAST_COMPLETED_ACTION_ATTR);
            if (actionFromUser != null && isRecentlyCompleted(user)) {
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
            user.setSingleAttribute(LAST_COMPLETED_ACTION_ATTR, actionId);
            user.setSingleAttribute(LAST_COMPLETED_ACTION_TIME_ATTR, String.valueOf(System.currentTimeMillis()));
        }
    }

    private static boolean isRecentlyCompleted(UserModel user) {
        String completedAt = user.getFirstAttribute(LAST_COMPLETED_ACTION_TIME_ATTR);
        if (completedAt == null) {
            return false;
        }
        try {
            return System.currentTimeMillis() - Long.parseLong(completedAt) <= COMPLETED_ACTION_TTL_MS;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
