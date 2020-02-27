package com.example.springauth.security.jwt;

import com.example.springauth.message.response.JwtResponse;
import com.example.springauth.model.out.UserOut;
import com.example.springauth.security.services.UserPrinciple;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpiration}")
    private int jwtExpiration;

    public JwtResponse generateJwtToken(Authentication authentication) {

        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();

        Map<String, Object> additionalInfo = new HashMap<>();

        additionalInfo.put("userId", userPrincipal.getId());
        additionalInfo.put("username", userPrincipal.getUsername());
        additionalInfo.put("authorities", userPrincipal.getAuthorities());
        additionalInfo.put("name", userPrincipal.getName());
        additionalInfo.put("email", userPrincipal.getEmail());

        return new JwtResponse(
                Jwts.builder()
                    .setSubject((userPrincipal.getUsername()))
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + jwtExpiration))
                    .setClaims(additionalInfo)
                    .signWith(SignatureAlgorithm.HS512, jwtSecret)
                    .compact(),
                new UserOut(
                        userPrincipal.getId(),
                        userPrincipal.getName(),
                        userPrincipal.getUsername(),
                        userPrincipal.getEmail()
                ),
                userPrincipal.getAuthorities().stream().map(a -> ((GrantedAuthority) a).toString()).collect(Collectors.toSet())
        );
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature -> Message: {} ", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token -> Message: {}", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token -> Message: {}", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token -> Message: {}", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty -> Message: {}", e);
        }

        return false;
    }
}