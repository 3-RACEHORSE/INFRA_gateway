package com.skyhorsemanpower.gatewayserver.security;

import com.skyhorsemanpower.gatewayserver.exception.CustomException;
import com.skyhorsemanpower.gatewayserver.exception.ResponseStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    public Claims getClaimsFromJwtToken(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(SECRET)
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
			Jws<Claims> claimsJws = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);
			String tokenType = claimsJws.getBody().get("TokenType", String.class);
			log.info("tokenType: {}", tokenType);
			if ("refresh".equals(tokenType)) {
				throw new CustomException(ResponseStatus.JWT_FAIL_WITH_REFRESH);
			}
		} catch (SignatureException e) {
			log.info("SignatureException >>>> {}", e.getMessage());
			throw new CustomException(ResponseStatus.INVALID_SIGNATURE_TOKEN);
		} catch (MalformedJwtException e) {
			log.info("MalformedJwtException >>>> {}", e.getMessage());
			throw new CustomException(ResponseStatus.DAMAGED_TOKEN);
		} catch (UnsupportedJwtException e) {
			log.info("UnsupportedJwtException >>>> {}", e.getMessage());
			throw new CustomException(ResponseStatus.UNSUPPORTED_TOKEN);
		} catch (ExpiredJwtException e) {
			log.info("ExpiredJwtException >>>> {}", e.getMessage());
			throw new CustomException(ResponseStatus.EXPIRED_TOKEN);
		} catch (IllegalArgumentException e) {
			log.info("IllegalArgumentException >>>> {}", e.getMessage());
			throw new CustomException(ResponseStatus.INVALID_TOKEN);
		} catch (Exception e) {
			log.info("Exception >>>> {}", e.getMessage());
			throw new CustomException(ResponseStatus.VERIFICATION_FAILED);
		}
	}
}
