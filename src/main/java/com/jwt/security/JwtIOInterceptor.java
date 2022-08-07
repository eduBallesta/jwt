package com.jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

@Component
public class JwtIOInterceptor implements HandlerInterceptor {

    @Value("${jms.jwt.token.auth.path}")
    private String AUTH_PATH;
    @Value("#{'${jms.jwt.excluded.path}'.split(',')}")
    private List<String> excluded;
    @Autowired
    private JwtIO jwtIO;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        boolean validate = false;
        String url = request.getRequestURI();
        if(url.equals(AUTH_PATH) || excluded(url)) {
            validate = true;
        }

        if(!validate && request.getHeader("Authorization") != null && !request.getHeader("Authorization").isEmpty()) {
            String token = request.getHeader("Authorization").replace("Bearer","");
            validate = !jwtIO.validateToken(token);
        }

        if(!validate){
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
        return validate;
    }

    private boolean excluded(String path) {
        boolean result = false;
        for(String exc: excluded) {

            if(exc.equals("#") && exc.equals(path)) {
                result = true;
            }
        }

        return result;
    }
}
