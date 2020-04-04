package com.qingrong.domain;

/**
 * @author HouQingrong
 * @date 2020-04-03 13:26
 */
public class TokenResponse {
    /**
     * (Reserved for future use) A token used to access allowed data. Currently, no data set has been defined for access.
     */
    String access_token;
    /**
     * The amount of time, in seconds, before the access token expires.
     */
    Integer expires_in;
    /**
     * A JSON Web Token that contains the user’s identity information.
     */
    String id_token;
    /**
     * The refresh token used to regenerate new access tokens. Store this token securely on your server.
     */
    String refresh_token;
    /**
     * The type of access token. It will always be bearer.
     */
    String token_type;
    /**
     * A string that describes the reason for the unsuccessful request. The string consists of a single allowed value.
     * Possible values: invalid_request, invalid_client, invalid_grant, unauthorized_client, unsupported_grant_type, invalid_scope
     */
    String error;


    public String getAccess_token() {
        return access_token;
    }

    public void setAccess_token(String access_token) {
        this.access_token = access_token;
    }

    public Integer getExpires_in() {
        return expires_in;
    }

    public void setExpires_in(Integer expires_in) {
        this.expires_in = expires_in;
    }

    public String getId_token() {
        return id_token;
    }

    public void setId_token(String id_token) {
        this.id_token = id_token;
    }

    public String getRefresh_token() {
        return refresh_token;
    }

    public void setRefresh_token(String refresh_token) {
        this.refresh_token = refresh_token;
    }

    public String getToken_type() {
        return token_type;
    }

    public void setToken_type(String token_type) {
        this.token_type = token_type;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }
}
