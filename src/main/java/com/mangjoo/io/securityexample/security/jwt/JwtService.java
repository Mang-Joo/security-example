package com.mangjoo.io.securityexample.security.jwt;

import com.mangjoo.io.securityexample.application.persistence.Role;
import com.mangjoo.io.securityexample.security.exception.ExpiredTokenException;
import com.mangjoo.io.securityexample.security.exception.JwtAllException;
import com.mangjoo.io.securityexample.security.exception.JwtSignatureException;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@Component
public class JwtService {

    @Value("${jwt.token.secret}")
    private String secretKey;

    @Value("${jwt.token.time}")
    private long tokenValidTime;

    // 시크릿 키
    // 유효시간
    // 알고리즘 선택
    // claim, 위변조 확인, 상했는지 parse,
    public String generateJwt(Long id, Role role) {

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime authTime = now.plusSeconds(tokenValidTime);

        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuedAt(Timestamp.valueOf(now))
                .setExpiration(Timestamp.valueOf(authTime))
                .setId(id.toString())
//                .claim("id", id)
                .claim("role", "ROLE_" + role)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public Claims parseJwt(String jwt) {
        try {
            return Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(jwt)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new ExpiredTokenException("토큰이 만료되었습니다.");
        } catch (SignatureException e) {
            throw new JwtSignatureException("토큰이 위조되었습니다.");
        } catch (JwtException e) {
            throw new JwtAllException("토큰이 잘못되었습니다.");
        }
    }

}
