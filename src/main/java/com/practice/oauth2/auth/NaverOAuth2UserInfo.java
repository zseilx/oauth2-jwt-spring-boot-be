package com.practice.oauth2.auth;

import java.util.Map;

public class NaverOAuth2UserInfo extends OAuth2UserInfo {
    
    public NaverOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }
    
    @SuppressWarnings("unchecked")
	public Map<String, Object> getResponse() {
		return (Map<String, Object>) attributes.get("response");
    }

    @Override
    public String getId() {
        Map<String, Object> response = getResponse();

        if (response == null) {
            return null;
        }

        return (String) response.get("id");
    }

    @Override
    public String getName() {
        Map<String, Object> response = getResponse();

        if (response == null) {
            return null;
        }

        return (String) response.get("nickname");
    }

    @Override
    public String getEmail() {
        Map<String, Object> response = getResponse();

        if (response == null) {
            return null;
        }

        return (String) response.get("email");
    }

    @Override
    public String getImageUrl() {
        Map<String, Object> response = getResponse();

        if (response == null) {
            return null;
        }

        return (String) response.get("profile_image");
    }
}