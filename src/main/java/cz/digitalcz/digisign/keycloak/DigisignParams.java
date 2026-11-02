package cz.digitalcz.digisign.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.keycloak.util.JsonSerialization;

/**
 * Parameters the DigiSign APP seals into the {@code digisign_params} request parameter (DigisignParamsEncoder):
 * compact JWE with {@code dir} + {@code A256GCM}, key = HKDF-SHA256(client secret, "digisign-params-v1").
 * Keycloak stores unknown request parameters as client notes, so the token arrives under {@link #CLIENT_NOTE}.
 */
public final class DigisignParams {
    public static final String CLIENT_NOTE = "client_request_param_digisign_params";

    private static final byte[] KEY_INFO = "digisign-params-v1".getBytes(StandardCharsets.UTF_8);
    private static final String KEY_ID = "v1";
    private static final int TAG_BITS = 128;

    private DigisignParams() {
    }

    /**
     * Claims of a token sealed for the client and not yet expired, null for anything else (forged, altered,
     * expired, other client or key, malformed) so the login theme falls back to its default content.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> unseal(String token, String clientSecret, String clientId, long nowEpochSeconds) {
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 5 || !parts[1].isEmpty() || clientSecret == null) {
                return null;
            }

            Map<String, Object> header = JsonSerialization.readValue(decode(parts[0]), Map.class);
            if (!"dir".equals(header.get("alg")) || !"A256GCM".equals(header.get("enc")) || !KEY_ID.equals(header.get("kid"))) {
                return null;
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(deriveKey(clientSecret), "AES"),
                new GCMParameterSpec(TAG_BITS, decode(parts[2]))
            );
            cipher.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));

            byte[] ciphertext = decode(parts[3]);
            byte[] tag = decode(parts[4]);
            byte[] sealed = Arrays.copyOf(ciphertext, ciphertext.length + tag.length);
            System.arraycopy(tag, 0, sealed, ciphertext.length, tag.length);

            Map<String, Object> claims = JsonSerialization.readValue(cipher.doFinal(sealed), Map.class);
            if (!clientId.equals(claims.get("aud")) || !(claims.get("exp") instanceof Number exp) || exp.longValue() < nowEpochSeconds) {
                return null;
            }

            return claims;
        } catch (Exception e) {
            return null;
        }
    }

    /** HKDF-SHA256 with an empty salt, one 32-byte output block — same as PHP hash_hkdf('sha256', $secret, 32, $info) */
    private static byte[] deriveKey(String clientSecret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] pseudoRandomKey = mac.doFinal(clientSecret.getBytes(StandardCharsets.UTF_8));

        mac.init(new SecretKeySpec(pseudoRandomKey, "HmacSHA256"));
        mac.update(KEY_INFO);
        mac.update((byte) 1);

        return mac.doFinal();
    }

    private static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
