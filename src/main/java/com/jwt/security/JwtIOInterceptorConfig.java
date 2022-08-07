package com.jwt.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Component
public class JwtIOInterceptorConfig implements WebMvcConfigurer {

    @Value("${jms.jwt.security.enabled:false}")
    private boolean securityEnabled;

    @Autowired
    private JwtIOInterceptor jwtIOInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        if(securityEnabled) {
            registry.addInterceptor(jwtIOInterceptor);
        }
    }
}
