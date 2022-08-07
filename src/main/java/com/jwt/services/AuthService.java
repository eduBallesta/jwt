package com.jwt.services;

import com.jwt.dto.JwtResponse;
import com.jwt.dto.User;
import com.jwt.security.JwtIO;
import com.jwt.utils.JwtIOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuthService {

    @Autowired
    private JwtIO jwtIO;
    @Autowired
    private JwtIOUtils jwtIOUtils;

    @Value("${jms.jwt.token.expires-in}")
    private int EXPIRES_IN;

    public JwtResponse login(String clientId, String clientSecret) {

        UUID uid = UUID.randomUUID();

        User user = User.builder()
                .name("Edu")
                .lastName("Ballesta")
                .role("ADMIN")
                .country("Colombia")
                .uid(uid.toString())
                .build();

        JwtResponse jwt = JwtResponse.builder()
        .tokenType("bearer")
        .accessToken(jwtIO.generateToken(user))
        .issuedAt(jwtIOUtils.getDateMillis() + "")
        .clientId(clientId)
        .expiresIn(EXPIRES_IN)
        .build();

        return jwt;
    }
}
