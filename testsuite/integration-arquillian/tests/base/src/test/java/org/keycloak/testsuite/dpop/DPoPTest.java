package org.keycloak.testsuite.dpop;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.*;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.*;
import org.keycloak.util.JWKSUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import java.security.MessageDigest;
import java.util.*;

import static org.junit.Assert.*;

public class DPoPTest extends AbstractTestRealmKeycloakTest {

    private static final String CONF_CLIENT_ID = "confidential-test-app";
    private static final String PUB_CLIENT_ID = "public-test-app";
    private static final String DPOP = "DPoP";
    private static final List<String> CLIENT_LIST = Arrays.asList("test-app", CONF_CLIENT_ID, PUB_CLIENT_ID);

    @Before
    public void enableDPoPToken() {
        // Enable DPoP Token
        for (String clientId : CLIENT_LIST) enableDPoPToken(clientId);
    }

    public void enableDPoPToken(String clientId) {
        // Enable DPoP Token
        ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm("test"), clientId);
        ClientRepresentation clientRep = clientResource.toRepresentation();
        OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep).setDPoPEnabled(true);
        clientResource.update(clientRep);
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        ClientRepresentation confApp = KeycloakModelUtils.createClient(testRealm, CONF_CLIENT_ID);
        confApp.setSecret("secret");
        confApp.setDirectAccessGrantsEnabled(Boolean.TRUE);

        ClientRepresentation pubApp = KeycloakModelUtils.createClient(testRealm, PUB_CLIENT_ID);
        pubApp.setPublicClient(Boolean.TRUE);
        pubApp.setDirectAccessGrantsEnabled(Boolean.TRUE);
    }


    @Test
    public void accessTokenRequestAuthCode() {
        ClientResource testClient = ApiUtil.findClientByClientId(adminClient.realm("test"), "test-app");
        assertTrue(OIDCAdvancedConfigWrapper.fromClientRepresentation(testClient.toRepresentation()).isDPoPEnabled());

        Map<String, String> headers = new HashMap<>();
        KeyPair keyPair = DPoPUtil.generateKeyPair(KeyType.RSA);
        JWK jwk = DPoPUtil.generateJwk(keyPair, Algorithm.RS256);
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);
        headers.put(DPOP, dPoP);
        String jwkThumbprint = JWKSUtils.computeThumbprint(jwk);
        oauth.requestHeaders(headers);

        oauth.doLogin("test-user@localhost", "password");
        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        OAuthClient.AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        assertEquals(200, response.getStatusCode());
        assertNotNull(response.getAccessToken());
        verifyDPoPTokenThumbPrint(response, jwkThumbprint, false);
    }

    @Test
    public void accessTokenRequestDirectGrant() {
        Map<String, String> headers = new HashMap<>();
        KeyPair keyPair = DPoPUtil.generateKeyPair(KeyType.RSA);
        JWK jwk = DPoPUtil.generateJwk(keyPair, Algorithm.RS256);
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);

        headers.put(DPOP, dPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);
        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(200, response.getStatusCode());
            assertNotNull(response.getAccessToken());
            verifyDPoPTokenThumbPrint(response, computeThumbprint(jwk), false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestES256() {
        Map<String, String> headers = new HashMap<>();
        KeyPair keyPair;
        String algorithm = Algorithm.ES256;

        keyPair = DPoPUtil.generateKeyPair(algorithm);
        JWK jwk = DPoPUtil.generateJwk(keyPair, algorithm);
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, algorithm);

        headers.put(DPOP, dPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);
        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(200, response.getStatusCode());
            assertNotNull(response.getAccessToken());
            verifyDPoPTokenThumbPrint(response, computeThumbprint(jwk), false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestPS256() {
        Map<String, String> headers = new HashMap<>();
        KeyPair keyPair;
        String algorithm = Algorithm.PS256;

        keyPair = DPoPUtil.generateKeyPair(algorithm);
        JWK jwk = DPoPUtil.generateJwk(keyPair, algorithm);
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, algorithm);

        headers.put(DPOP, dPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);
        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(200, response.getStatusCode());
            assertNotNull(response.getAccessToken());
            verifyDPoPTokenThumbPrint(response, computeThumbprint(jwk), false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithAlreadyUsedDPoP() {
        Map<String, String> headers = new HashMap<>();
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Algorithm.RS256);
        headers.put(DPOP, dPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("DPoP proof has already been used", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithExpiredDPoP() {
        Map<String, String> headers = new HashMap<>();
        String expiredDPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", (Time.currentTime() - 20), Algorithm.RS256);
        headers.put(DPOP, expiredDPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("DPoP proof is not active", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithInactiveDPoP() {
        Map<String, String> headers = new HashMap<>();
        String inactiveDPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", (Time.currentTime() + 10), Algorithm.RS256);
        headers.put(DPOP, inactiveDPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("DPoP proof is not active", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @Ignore
    // Absent Public key in DPoP validating throws NullPointerException
    public void accessTokenRequestWithAbsentPublicKeyInDPoP() {
        Map<String, String> headers = new HashMap<>();
        CryptoIntegration.init(DefaultCryptoProvider.class.getClassLoader());
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Algorithm.RS256);

        String dPoPWithoutHeader = dPoP.substring(dPoP.indexOf(".") + 1);
        String jwkWithoutPublicKey = "{ \"typ\": \"dpop+jwt\", " +
                "\"alg\": \"RS256\"," +
                "\"kid\": \"Ke6VXs-2U1f5TdCqKj-e3lDL_VbkDHtpW1U3BakgvcM\"" +
                "\"jwk\": " + " {" +
                "\"kid\": \"Ke6VXs-2U1f5TdCqKj-e3lDL_VbkDHtpW1U3BakgvcM\"," +
                "    \"kty\": \"RSA\"," +
                "    \"alg\": \"RS256\"," +
                "    \"use\": \"sig\"" +
                "}" +
                "}";
        String encodedHeader = Base64Url.encode(jwkWithoutPublicKey.getBytes(StandardCharsets.UTF_8));
        String dPoPWithoutPublicKey = encodedHeader + "." + dPoPWithoutHeader;

        System.out.println(dPoP);
        headers.put(DPOP, dPoPWithoutPublicKey);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("DPoP proof is not active", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithAbsentJWK() {
        Map<String, String> headers = new HashMap<>();
        CryptoIntegration.init(DefaultCryptoProvider.class.getClassLoader());

        KeyPair keyPair = DPoPUtil.generateKeyPair(KeyType.RSA);
        byte[] dPoPProof = DPoPUtil.generateDPoPProofPayload(oauth.getAccessTokenUrl(), "POST", Time.currentTime());
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
        keyWrapper.setAlgorithm(Algorithm.RS256);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setType(keyPair.getPublic().getAlgorithm());
        keyWrapper.setUse(KeyUse.SIG);


        AsymmetricSignatureSignerContext signatureSignerContext = new AsymmetricSignatureSignerContext(keyWrapper);
        String dPoPWithAbsentJWK = new JWSBuilder().type("dpop+jwt").content(dPoPProof).sign(signatureSignerContext);
        headers.put(DPOP, dPoPWithAbsentJWK);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("No JWK in DPoP header", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithAbsentDPoP() {
        Map<String, String> headers = new HashMap<>();
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("DPoP proof is missing", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithInvalidJWTHeader() {
        Map<String, String> headers = new HashMap<>();
        CryptoIntegration.init(DefaultCryptoProvider.class.getClassLoader());
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Algorithm.RS256);

        String dPoPWithoutHeader = dPoP.substring(dPoP.indexOf(".") + 1);
        String jwkWithoutPublicKey = "{ \"typ\": \"dpop+jwt\", " +
                "\"alg\": \"RS256\"," +
                "\"kid\": {}" +
                "}";
        String encodedHeader = Base64Url.encode(jwkWithoutPublicKey.getBytes(StandardCharsets.UTF_8));
        String dPoPWithoutPublicKey = encodedHeader + "." + dPoPWithoutHeader;

        System.out.println(dPoP);
        headers.put(DPOP, dPoPWithoutPublicKey);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("DPoP header verification failure", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithWrongJwtType() {
        Map<String, String> headers = new HashMap<>();
        CryptoIntegration.init(DefaultCryptoProvider.class.getClassLoader());
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Algorithm.RS256);

        String dPoPWithoutHeader = dPoP.substring(dPoP.indexOf(".") + 1);
        String jwkWithoutPublicKey = "{ \"typ\": \"jwt\", " +
                "\"alg\": \"RS256\"," +
                "\"kid\": 123" +
                "}";
        String encodedHeader = Base64Url.encode(jwkWithoutPublicKey.getBytes(StandardCharsets.UTF_8));
        String dPoPWithoutPublicKey = encodedHeader + "." + dPoPWithoutHeader;

        System.out.println(dPoP);
        headers.put(DPOP, dPoPWithoutPublicKey);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("Invalid or missing type in DPoP header: jwt", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void accessTokenRequestWithUnsupportedEncryptionAlgorithm() {
        Map<String, String> headers = new HashMap<>();
        CryptoIntegration.init(DefaultCryptoProvider.class.getClassLoader());
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Algorithm.RS256);

        String dPoPWithoutHeader = dPoP.substring(dPoP.indexOf(".") + 1);
        String jwkWithoutPublicKey = "{ \"typ\": \"dpop+jwt\", " +
                "\"alg\": \"HS256\"," +
                "\"kid\": \"Ke6VXs-2U1f5TdCqKj-e3lDL_VbkDHtpW1U3BakgvcM\"" +
                "}";
        String encodedHeader = Base64Url.encode(jwkWithoutPublicKey.getBytes(StandardCharsets.UTF_8));
        String dPoPWithoutPublicKey = encodedHeader + "." + dPoPWithoutHeader;

        System.out.println(dPoP);
        headers.put(DPOP, dPoPWithoutPublicKey);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertEquals(400, response.getStatusCode());
            assertEquals("invalid_dpop_proof", response.getError());
            assertEquals("Unsupported DPoP algorithm: HS256", response.getErrorDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void refreshTokenRequestWithCodeFlow() {
        oauth.doLogin("test-user@localhost", "password");
        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        Map<String, String> headers = new HashMap<>();

        KeyPair keyPair = DPoPUtil.generateKeyPair(KeyType.RSA);
        JWK jwk = DPoPUtil.generateJwk(keyPair, Algorithm.RS256);
        String thumbprint = computeThumbprint(jwk);
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);

        headers.put(DPOP, dPoP);
        oauth.requestHeaders(headers);

        OAuthClient.AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");
        assertEquals(200, response.getStatusCode());

        String refreshTokenDPoP = DPoPUtil.generateDPoPProof(oauth.getRefreshTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);
        Map<String, String> refreshTokenHeaders = new HashMap<>();
        refreshTokenHeaders.put(DPOP, refreshTokenDPoP);
        oauth.requestHeaders(refreshTokenHeaders);
        String refreshToken = response.getRefreshToken();
        verifyDPoPTokenThumbPrint(response, thumbprint, false);
        response = oauth.doRefreshTokenRequest(refreshToken, "password");
        assertEquals(200, response.getStatusCode());
    }

    @Test
    public void refreshTokenRequestWithPublicClient() {
        Map<String, String> headers = new HashMap<>();

        KeyPair keyPair = DPoPUtil.generateKeyPair(KeyType.RSA);
        JWK jwk = DPoPUtil.generateJwk(keyPair, Algorithm.RS256);
        String thumbprint = computeThumbprint(jwk);
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);
        String refreshTokenString;

        headers.put(DPOP, dPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(PUB_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertNotNull(response.getAccessToken());
            assertEquals(200, response.getStatusCode());
            verifyDPoPTokenThumbPrint(response, thumbprint, true);
            refreshTokenString = response.getRefreshToken();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String refreshTokenDPoP = DPoPUtil.generateDPoPProof(oauth.getRefreshTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);
        Map<String, String> refreshTokenHeaders = new HashMap<>();
        refreshTokenHeaders.put(DPOP, refreshTokenDPoP);
        oauth.requestHeaders(refreshTokenHeaders);

        OAuthClient.AccessTokenResponse refreshTokenResponse = oauth.doRefreshTokenRequest(refreshTokenString, null);
        assertEquals(200, refreshTokenResponse.getStatusCode());
        assertNotNull(refreshTokenResponse.getAccessToken());
        verifyDPoPTokenThumbPrint(refreshTokenResponse, thumbprint, true);
    }

    @Test
    public void refreshTokenRequestWithConfidentialClient() {
        Map<String, String> headers = new HashMap<>();

        KeyPair keyPair = DPoPUtil.generateKeyPair(KeyType.RSA);
        JWK jwk = DPoPUtil.generateJwk(keyPair, Algorithm.RS256);
        String thumbprint = computeThumbprint(jwk);
        String dPoP = DPoPUtil.generateDPoPProof(oauth.getAccessTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);
        String refreshTokenString;

        headers.put(DPOP, dPoP);
        oauth.requestHeaders(headers);
        oauth.clientId(CONF_CLIENT_ID);

        try {
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password", null);
            assertNotNull(response.getAccessToken());
            assertEquals(200, response.getStatusCode());
            verifyDPoPTokenThumbPrint(response, thumbprint, false);
            JWSInput jws = new JWSInput(response.getRefreshToken());
            RefreshToken rt = jws.readJsonContent(RefreshToken.class);
            assertNull(rt.getConfirmation());
            refreshTokenString = response.getRefreshToken();

            String refreshTokenDPoP = DPoPUtil.generateDPoPProof(oauth.getRefreshTokenUrl(), "POST", Time.currentTime(), jwk, keyPair, Algorithm.RS256);
            Map<String, String> refreshTokenHeaders = new HashMap<>();
            refreshTokenHeaders.put(DPOP, refreshTokenDPoP);
            oauth.requestHeaders(refreshTokenHeaders);

            OAuthClient.AccessTokenResponse refreshTokenResponse = oauth.doRefreshTokenRequest(refreshTokenString, "secret");
            assertEquals(200, refreshTokenResponse.getStatusCode());
            assertNotNull(refreshTokenResponse.getAccessToken());
            verifyDPoPTokenThumbPrint(refreshTokenResponse, thumbprint, false);
            jws = new JWSInput(refreshTokenResponse.getRefreshToken());
            rt = jws.readJsonContent(RefreshToken.class);
            assertNull(rt.getConfirmation());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void verifyDPoPTokenThumbPrint(OAuthClient.AccessTokenResponse response, String thumbprint, boolean checkRefreshToken) {
        AccessToken at = null;
        try {
            JWSInput jws = new JWSInput(response.getAccessToken());
            at = jws.readJsonContent(AccessToken.class);
        } catch (JWSInputException e) {
            Assert.fail(e.toString());
        }
        assertTrue(MessageDigest.isEqual(thumbprint.getBytes(), at.getConfirmation().getKeyThumbprint().getBytes()));

        if (checkRefreshToken) {
            RefreshToken rt;
            try {
                JWSInput jws = new JWSInput(response.getRefreshToken());
                rt = jws.readJsonContent(RefreshToken.class);
            } catch (JWSInputException e) {
               throw new RuntimeException(e);
            }
            assertTrue(MessageDigest.isEqual(thumbprint.getBytes(), rt.getConfirmation().getKeyThumbprint().getBytes()));
        }
    }

    private String computeThumbprint(JWK jwk) {
        String thumbprint;
        switch (jwk.getKeyType()) {
            case KeyType.RSA: {
                RSAPublicJWK rsaPublicJWK = (RSAPublicJWK) jwk;
                rsaPublicJWK.setOtherClaims("n", rsaPublicJWK.getModulus());
                rsaPublicJWK.setOtherClaims("e", rsaPublicJWK.getPublicExponent());
                rsaPublicJWK.setModulus(null);
                rsaPublicJWK.setPublicExponent(null);
                thumbprint = JWKSUtils.computeThumbprint(rsaPublicJWK);
                break;
            }
            case KeyType.EC: {
                ECPublicJWK ecPublicJWK = (ECPublicJWK) jwk;
                ecPublicJWK.setOtherClaims("x", ecPublicJWK.getX());
                ecPublicJWK.setOtherClaims("y", ecPublicJWK.getY());
                ecPublicJWK.setOtherClaims("crv", ecPublicJWK.getCrv());
                thumbprint = JWKSUtils.computeThumbprint(ecPublicJWK);
                break;
            }
            default:
                throw new IllegalArgumentException("KeyType not supported: " + jwk.getKeyType());
        }
        return thumbprint;
    }
}
