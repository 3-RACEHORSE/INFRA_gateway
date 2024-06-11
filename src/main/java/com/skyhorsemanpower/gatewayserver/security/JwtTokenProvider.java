package com.skyhorsemanpower.gatewayserver.security;

import com.skyhorsemanpower.gatewayserver.exception.CustomException;
import com.skyhorsemanpower.gatewayserver.exception.ResponseStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Component
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    private final Environment env;

    @Value("${JWT.SECRET_KEY}")
    private String SECRET;

    private Claims getClaimsFromJwtToken(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(SECRET.getBytes())
                .build()
                .parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public Date getExpiredTime(String token) {
        return getClaimsFromJwtToken(token).getExpiration();
    }

    public void validateJwtToken(String token) {
        try {
            Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);
        } catch (SignatureException e) {
            throw new CustomException(ResponseStatus.INVALID_SIGNATURE_TOKEN);
        } catch (MalformedJwtException e) {
            throw new CustomException(ResponseStatus.DAMAGED_TOKEN);
        } catch (UnsupportedJwtException e) {
            throw new CustomException(ResponseStatus.UNSUPPORTED_TOKEN);
        } catch (ExpiredJwtException e) {
            throw new CustomException(ResponseStatus.EXPIRED_TOKEN);
        } catch (IllegalArgumentException e) {
            throw new CustomException(ResponseStatus.INVALID_TOKEN);
        } catch (RuntimeException e) {
            throw new CustomException(ResponseStatus.VERIFICATION_FAILED);
        }
    }
}
