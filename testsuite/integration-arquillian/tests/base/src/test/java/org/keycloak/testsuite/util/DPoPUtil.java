package org.keycloak.testsuite.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.*;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.testsuite.model.DPoPPayload;

import java.security.*;
import java.util.UUID;

public class DPoPUtil {
     public static String generateDPoPProof(String url, String method, String algorithm) {
         return generateDPoPProof(url, method, Time.currentTime(), algorithm);

     }

    public static String generateDPoPProof(String url, String method, int issuedAt, String algorithm) {
        KeyPair keyPair = generateKeyPair(algorithm);
        JWK jwk = generateJwk(keyPair, algorithm);
        return generateDPoPProof(url, method, issuedAt, jwk, keyPair, algorithm);
    }

    public static String generateDPoPProof(String url, String method, int issuedAt, JWK jwk, KeyPair keyPair, String algorithm) {
        byte[] dPoPProof = generateDPoPProofPayload(url, method, issuedAt);
        String dPoP = generateJWT(dPoPProof, keyPair, jwk, algorithm);
        return dPoP;
    }

    public static KeyPair generateKeyPair(String algorithm) {
        try {
            if (algorithm.startsWith("ES")) {
                return KeyPairGenerator.getInstance("EC").generateKeyPair();
            }

            if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
                return KeyPairGenerator.getInstance("RSA").generateKeyPair();
            }
            throw new IllegalArgumentException("Algorithm not supported " + algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    public static JWK generateJwk(KeyPair keyPair, String algorithm) {
        try {
            PublicKey publicKey = keyPair.getPublic();
            JWKBuilder jwkBuilder = JWKBuilder.create()
                    .kid(KeyUtils.createKeyId(publicKey))
                    .algorithm(algorithm);

             if (algorithm.startsWith("ES")) {
                 return jwkBuilder.ec(publicKey);
             }
             if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
                 return jwkBuilder.rsa(publicKey);
             }

             throw new IllegalArgumentException("Algorithm not supported " + algorithm);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }
    }

    public static byte[] generateDPoPProofPayload(String url, String method, int issuedAt) {
        try {
            return new ObjectMapper().writeValueAsBytes(generatePayload(url, method, issuedAt));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateJWT(byte[] dPoPProof, KeyPair keyPair, JWK jwk, String algorithm) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
        keyWrapper.setAlgorithm(algorithm);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setType(keyPair.getPublic().getAlgorithm());
        keyWrapper.setUse(KeyUse.SIG);

        AsymmetricSignatureSignerContext signatureSignerContext = new AsymmetricSignatureSignerContext(keyWrapper);
        return new JWSBuilder().jwk(jwk).type("dpop+jwt").content(dPoPProof).sign(signatureSignerContext);
    }

    private static DPoPPayload generatePayload(String url, String method, int issuedAt) {
        DPoPPayload payload = new DPoPPayload();
        payload.setHtu(url);
        payload.setHtm(method);
        payload.setJti(UUID.randomUUID().toString());
        payload.setIat(issuedAt);
        return payload;
    }
}
