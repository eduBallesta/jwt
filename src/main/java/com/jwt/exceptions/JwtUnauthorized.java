package com.jwt.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class JwtUnauthorized extends Exception {

    private static final  long serialVersionUID = 94909049049094049L;

    public JwtUnauthorized(String message) {
        super(message);
    }

}
