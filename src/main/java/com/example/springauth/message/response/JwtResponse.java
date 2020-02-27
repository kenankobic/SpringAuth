package com.example.springauth.message.response;

import com.example.springauth.model.out.UserOut;

import java.util.Set;

public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private UserOut user;
    private Set<String> authorities;

    public JwtResponse(String accessToken, UserOut user, Set<String> authorities) {
        this.token = accessToken;
        this.user = user;
        this.authorities = authorities;
    }

    public String getAccessToken() {
        return token;
    }

    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }

    public String getTokenType() {
        return type;
    }

    public void setTokenType(String tokenType) {
        this.type = tokenType;
    }

    public UserOut getUser() {
        return user;
    }

    public void setUser(UserOut user) {
        this.user = user;
    }

    public Set<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Set<String> authorities) {
        this.authorities = authorities;
    }
}