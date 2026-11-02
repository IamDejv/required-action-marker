package cz.digitalcz.digisign.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

class DigisignParamsTest {
    /** DigisignParamsEncoder (APP) output for test-client/test-secret at 2026-11-02T12:00:00Z, valid for one hour */
    private static final String TOKEN = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoidjEifQ..-6GWUFP8ZvkKhgXU.de9JqQUaXQxVxU0IHTwS1PKpjZ4GTpzI0YQSSJYCnVAFS_19i2xWAJOwWeU4MW3JvHmyn_7wZxrSJawwoEOks0pI0XxH33uNfC5BlodPbbBYrdYXofEnHFLXNzIiUGaUraqmr7P1NPgbCM6CtOgEx8QGUYqOTjY6tUPjX3tthkGc4TGbixEcZhpLXJn1bYdAN623stpFDAdC0ozJYQ.V5Lhr0dGaRqh-3WBu9pvIg";
    private static final String SECRET = "test-secret";
    private static final String CLIENT_ID = "test-client";
    private static final long NOW = 1793620800L + 60;

    @Test
    void unsealsPhpToken() {
        Map<String, Object> claims = DigisignParams.unseal(TOKEN, SECRET, CLIENT_ID, NOW);

        assertNotNull(claims);
        assertEquals("CONFIGURE_TOTP", claims.get("kc_action"));
        assertEquals(Map.of("inviter", "Jana Nováková", "workspace", "NašeFirma a.s."), claims.get("invitation"));
    }

    @Test
    void rejectsWrongSecret() {
        assertNull(DigisignParams.unseal(TOKEN, "other-secret", CLIENT_ID, NOW));
    }

    @Test
    void rejectsOtherClient() {
        assertNull(DigisignParams.unseal(TOKEN, SECRET, "other-client", NOW));
    }

    @Test
    void rejectsExpired() {
        assertNull(DigisignParams.unseal(TOKEN, SECRET, CLIENT_ID, 1793624400L + 1));
    }

    @Test
    void rejectsTamperedCiphertext() {
        String[] parts = TOKEN.split("\\.", -1);
        char first = parts[3].charAt(0);
        parts[3] = (first == 'A' ? 'B' : 'A') + parts[3].substring(1);

        assertNull(DigisignParams.unseal(String.join(".", parts), SECRET, CLIENT_ID, NOW));
    }

    @Test
    void rejectsOtherKid() {
        String[] parts = TOKEN.split("\\.", -1);
        parts[0] = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"kid\":\"v2\"}".getBytes(StandardCharsets.UTF_8));

        assertNull(DigisignParams.unseal(String.join(".", parts), SECRET, CLIENT_ID, NOW));
    }

    @Test
    void rejectsMalformed() {
        assertNull(DigisignParams.unseal("abc", SECRET, CLIENT_ID, NOW));
        assertNull(DigisignParams.unseal("a.b.c.d", SECRET, CLIENT_ID, NOW));
        assertNull(DigisignParams.unseal("", SECRET, CLIENT_ID, NOW));
    }
}
