package com.skyhorsemanpower.gatewayserver.filter;

import com.skyhorsemanpower.gatewayserver.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import java.util.Date;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AdminHeaderFilter extends
    AbstractGatewayFilterFactory<AdminHeaderFilter.Config> {
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public AdminHeaderFilter(JwtTokenProvider jwtTokenProvider) {
        super(Config.class);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public static class Config {

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            HttpHeaders headers = request.getHeaders();
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No Authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = headers.get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer ", "");


            jwtTokenProvider.adminValidateJwtToken(jwt);

            // admin인지 아닌지 검증
            Claims claims = jwtTokenProvider.getClaimsFromJwtToken(jwt);
            String role = claims.get("role", String.class);
            if (role == null || !role.equals("admin")) {
                return onError(exchange, "admin 아님", HttpStatus.FORBIDDEN);
            }

            // 엑세스토큰 유효기간 검증
            Date expiredTime = jwtTokenProvider.getExpiredTime(jwt);
            if (expiredTime.before(new Date())) {
                return onError(exchange, "토큰 만료", HttpStatus.UNAUTHORIZED);
            }

            ServerHttpRequest newRequest = request.mutate()
                .header("X-AUTH-TOKEN", jwt)
                .build();

            return chain.filter(exchange.mutate().request(newRequest).build());

        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage,
        HttpStatus httpStatus) {
        log.error(errorMessage);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        return response.setComplete();
    }
}
