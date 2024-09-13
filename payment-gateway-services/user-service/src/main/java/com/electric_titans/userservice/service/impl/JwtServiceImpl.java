package com.electric_titans.userservice.service.impl;

import com.electric_titans.userservice.security.CustomUserDetails;
import com.electric_titans.userservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
@Slf4j
@Service
public class JwtServiceImpl implements JwtService {

    private final String secretKey = "ctg8mN+IeaDnxyso2lt8Mba2YIsahcyiuVDAuUH20RI=";
    @Value("${jwt.expiration-time}")
    private long jwtExpiration;

    @Override
    public String extractUsername(String token) {
        log.debug("Extracting username from token: {}", token);
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        if (claimsResolver == null) {
            log.warn("Claims resolver is null");
            return null;
        }

        // Add this block to check the token structure
        if (token == null || !token.contains(".")) {
            log.error("Invalid token structure: {}", token);
            throw new IllegalArgumentException("Invalid token structure");
        }

        try {
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
        } catch (Exception e) {
            log.error("Error extracting claims: {}", e.getMessage(), e);
            return null;
        }
    }

    @Override
    public String generateToken(CustomUserDetails userDetails) {
        log.debug("Generating token for user: {}", userDetails.getEmail());
        return generateToken(new HashMap<>(), userDetails);
    }

    @Override
    public String generateToken(Map<String, Object> extraClaims, CustomUserDetails userDetails) {
        log.debug("Generating token with extra claims: {} for user: {}", extraClaims, userDetails.getUsername());
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    @Override
    public long getExpirationTime() {
        log.debug("Getting expiration time: {}", jwtExpiration);
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            CustomUserDetails userDetails,
            long expiration
    ) {
        log.debug("Building token for user: {}", userDetails.getEmail());
        try {
            String token = Jwts
                    .builder()
                    .setClaims(extraClaims)
                    .setSubject(userDetails.getEmail())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + expiration))
                    .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                    .compact();
            log.debug("Generated token: {}", token);
            return token;
        } catch (Exception e) {
            log.error("Error building token: {}", e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public boolean isTokenValid(String token, CustomUserDetails userDetails) {
        final String username = extractUsername(token);
        log.info("Token username: {}", username);
        return (username.equals(userDetails.getEmail())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            log.error("Error checking token expiration: {}", e.getMessage(), e);
            return true;
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            log.error("Error extracting claims from token: {}", e.getMessage(), e);
            throw e;
        }
    }

    private Key getSignInKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secretKey);
            if (keyBytes.length != 32) {
                throw new IllegalArgumentException("Invalid secret key length. Expected 32 bytes.");
            }
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            log.error("Error decoding secret key: {}", e.getMessage(), e);
            throw new IllegalArgumentException("Invalid secret key", e);
        }
    }

    @Override
    public String extractTokenFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            log.debug("Extracted Token from header: {}", token);
            return token;
        }
        return null;
    }
}
