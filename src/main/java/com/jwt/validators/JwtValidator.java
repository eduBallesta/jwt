package com.jwt.validators;

import com.jwt.exceptions.JwtUnauthorized;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

import java.util.Objects;

@Component
public class JwtValidator {

    public static final String CLIENT_CREDENTIALS = "client_credentials";

    public void validate(MultiValueMap<String, String> paramMap, String grantType) throws JwtUnauthorized {

        if(grantType.isEmpty() || !grantType.equals(CLIENT_CREDENTIALS)) {
            message("grant_type field is invalid");
        }

        if(Objects.isNull(paramMap) ||
           Objects.isNull(paramMap.getFirst("client_id")) ||
           paramMap.getFirst("client_id").isEmpty() ||
           Objects.isNull(paramMap.getFirst("client_secret")) ||
           paramMap.getFirst("client_secret").isEmpty()) {
                message("client_id or client_secret field is invalid");
        }
    }

    private void message(String message) throws JwtUnauthorized {
        throw new JwtUnauthorized(message);
    }

}
