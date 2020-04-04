package com.qingrong.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.qingrong.domain.JwsHeader;
import com.qingrong.domain.TokenResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.jose4j.base64url.Base64;
import org.jose4j.base64url.Base64Url;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * server side authentication identityToken and authorizationCode.
 * @author HouQingrong
 * @date 2020/4/4 20:32
 */
public class AppleIdAuthUtil {
    private static final Logger logger = LoggerFactory.getLogger(AppleIdAuthUtil.class);

    private static final String TEAM_ID = ""; // TODO: replace to your site's team id
    private static final String CLIENT_ID = ""; // TODO: replace to your site's client id
    private static final String KEY_ID = ""; // TODO: replace to your site's key id
    private static final String APPLE_PUBLIC_KEY_URL = "https://appleid.apple.com/auth/keys";
    private static final String APPLE_AUTH_URL = "https://appleid.apple.com/auth/token";

    private static PrivateKey privateKey;
    private static Map<String, PublicKey> publicKeys;

    /**
     * Check whether the current user's request is legal.
     * @param appleUserId apple user id from client
     * @param identityToken     a jws string of user identity
     * @param authorizationCode authorization code for verify identityToken
     */
    public static boolean verifyAppleCode(String appleUserId, String identityToken, String authorizationCode) {
        boolean result = false;
        try {
            // identityToken decoded to jws format object, perform time verification, and use the apple public key to verify the signature
            JwsHeader header = decodeHeader(appleUserId, identityToken);
            PublicKey publicKey = getAppleIdPublicKey(header);
            JwtParser jwtParser = Jwts.parser().setSigningKey(publicKey);
            Jws<Claims> jws = jwtParser.parseClaimsJws(identityToken);

            // Got the subject in identityToken
            Claims clientJwsBody = jws.getBody();
            String clientSubject = clientJwsBody.getSubject();

            // Go to the apple server to verify the authorizationCode, and get the user identityToken issued by the server
            PrivateKey appleIdPrivateKey = getAppleIdPrivateKey();
            TokenResponse tokenResponse = appleServerAuth(authorizationCode, appleIdPrivateKey);
            if (tokenResponse.getError() != null && tokenResponse.getError().length() > 0) {
                logger.warn(String.format("[verifyAppleCode]verify apple user[%s] identity token failed. reason: %s.", appleUserId, tokenResponse.getError()));
                return false;
            }

            // Decode the identityToken issued by the apple server into jws format object, perform time verification, and use the apple public key to verify the signature
            identityToken = tokenResponse.getId_token();
            header = decodeHeader(appleUserId, identityToken);
            publicKey = getAppleIdPublicKey(header);
            jwtParser = Jwts.parser().setSigningKey(publicKey);
            jws = jwtParser.parseClaimsJws(identityToken);

            // Compare whether the subject of the client is equals with the subject delivered by the server
            Claims serverJwsBody = jws.getBody();
            result = serverJwsBody.getSubject().equals(clientSubject);
            if (!result) {
                ObjectMapper jacksonMapper = new ObjectMapper();
                logger.warn(String.format("[verifyAppleCode]verify apple user[%s] identity token failed. subject not match. %s, %s.",
                        appleUserId, jacksonMapper.writeValueAsString(clientJwsBody), jacksonMapper.writeValueAsString(serverJwsBody)));
            }
        } catch (Throwable t) {
            logger.warn(String.format("[verifyAppleCode]verify apple user[%s] identity token failed. reason: %s.", appleUserId, t.getMessage()));
        }
        return result;
    }

    /**
     * Extract the header part of the string in jws format
     */
    private static JwsHeader decodeHeader(String appleUserId, String identityToken) {
        JwsHeader jwsHeader = null;
        try {
            String[] arrToken = identityToken.split("\\.");
            if (arrToken == null || arrToken.length != 3) {
                return null;
            }

            String text = new String(Base64.decode(arrToken[0]), "utf-8");
            ObjectMapper jacksonMapper = new ObjectMapper();
            jwsHeader = jacksonMapper.readValue(text, JwsHeader.class);
        } catch (Throwable t) {
            logger.warn(String.format("[decodeHeader]verify apple user[%s] identity token failed. reason: %s.", appleUserId, t.getMessage()));
        }
        return jwsHeader;
    }

    /**
     * Use the apple.com/auth/token service to verify the authorizationCode of the current request.
     * ref: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
     */
    private static TokenResponse appleServerAuth(String authorizationCode, PrivateKey privateKey) throws IOException {
        String clientSecret = Jwts.builder()
                .setHeaderParam("kid", KEY_ID)
                .setIssuer(TEAM_ID)
                .setAudience("https://appleid.apple.com")
                .setSubject(CLIENT_ID)
                .setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 5)))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .signWith(SignatureAlgorithm.ES256, privateKey)
                .compact();
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> param = new HashMap<>();
        param.put("client_id", CLIENT_ID);
        param.put("client_secret", clientSecret);
        param.put("code", authorizationCode);
        param.put("grant_type", "authorization_code");
        String responseStr = HttpClientUtils.doPost(APPLE_AUTH_URL, param);
        TokenResponse tokenResponse = objectMapper.readValue(responseStr, TokenResponse.class);
        return tokenResponse;
    }

    /**
     * Obtain the apple public key.
     * Because there are multiple groups of public keys provided by apple, need to determine which group of public keys to use.
     * Getting the kid and alg from header, after that can find the corresponding public key string and converted to PublicKey object.
     */
    private static PublicKey getAppleIdPublicKey(JwsHeader header) {
        PublicKey publicKey = null;
        try {
            if (publicKeys == null || publicKeys.size() == 0) {
                // Get publicKey string from appleServer
                String publicKeyStr = HttpClientUtils.doGet(APPLE_PUBLIC_KEY_URL);
                if (publicKeyStr == null || publicKeyStr.length() == 0) {
                    return null;
                }
                publicKeys = new HashMap<>();
                ObjectMapper objectMapper = new ObjectMapper();

                Map maps = objectMapper.readValue(publicKeyStr, Map.class);
                List<Map> keys = (List<Map>) maps.get("keys");
                // converted to PublicKey object.
                for (Map key : keys) {
                    if (key != null) {
                        byte[] nBytes = Base64Url.decode(key.get("n").toString());
                        byte[] eBytes = Base64Url.decode(key.get("e").toString());
                        BigInteger modulus = new BigInteger(1, nBytes);
                        BigInteger publicExponent = new BigInteger(1, eBytes);
                        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
                        String algorithm = key.get("kty").toString();  //kty will be "RSA"
                        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                        publicKey = keyFactory.generatePublic(publicKeySpec);

                        String mapKey = String.format("%s_%s", key.get("kid"), key.get("alg"));
                        publicKeys.put(mapKey, publicKey);
                    }
                }
            }
            String headerKey = String.format("%s_%s", header.getKid(), header.getAlg());
            publicKey = publicKeys.get(headerKey);
        } catch (Throwable t) {
            logger.error(String.format("[getAppleIdPublicKey]query apple public key failed. reason: %s", t.getMessage()));
        }
        return publicKey;
    }

    private static PrivateKey getAppleIdPrivateKey() {
        if (privateKey != null) {
            return privateKey;
        }

        try {
            // Get privateKey from local file
            String path = AppleIdAuthUtil.class.getResource("/").getPath()+ "AuthKey.p8";
            PEMParser pemParser = new PEMParser(new FileReader(path));
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo object = (PrivateKeyInfo) pemParser.readObject();
            privateKey = converter.getPrivateKey(object);
        } catch (Throwable t) {
            logger.error(String.format("[getAppleIdPrivateKey]parse local p8 file to private key failed. %s",t.getMessage()));
        }
        return privateKey;
    }

    public static void main(String[] args) {
        String userId = "";
        String identityToken = "";
        String authorizationCode = "";
        verifyAppleCode(userId, identityToken, authorizationCode);
    }

}
