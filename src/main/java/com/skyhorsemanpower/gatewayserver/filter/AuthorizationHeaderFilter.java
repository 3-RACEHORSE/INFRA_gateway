package com.skyhorsemanpower.gatewayserver.filter;

import com.skyhorsemanpower.gatewayserver.exception.CustomException;
import com.skyhorsemanpower.gatewayserver.exception.ResponseStatus;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends
    AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final SecretKey key;

    public AuthorizationHeaderFilter(@Value("${JWT.SECRET_KEY}") String key) {
        super(Config.class);
        byte[] keyBytes = Decoders.BASE64.decode(key);
        this.key = new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest req = exchange.getRequest();
            HttpHeaders header = req.getHeaders();

            if (!header.containsKey(HttpHeaders.AUTHORIZATION)) {
                throw new CustomException(ResponseStatus.NOT_FOUND_TOKEN);
            }

            String authorization = header.get(HttpHeaders.AUTHORIZATION).get(0);
            if (authorization == null || !authorization.startsWith("Bearer")) {
                throw new CustomException(ResponseStatus.INVALID_TOKEN);
            }

            String jwt = authorization.substring(7);
            isValid(jwt);
            return chain.filter(exchange);
        };
    }

    private void isValid(String jwt) {

        try {
            Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwt)
                .getBody()
                .getSubject();
        } catch (ExpiredJwtException e) {
            throw new CustomException(ResponseStatus.EXPIRED_TOKEN);
        } catch (Exception e) {
            throw new CustomException(ResponseStatus.INVALID_TOKEN);
        }
    }

    public static class Config {

    }
}