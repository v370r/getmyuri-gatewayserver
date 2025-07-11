package com.getmyuri.gatewayservice.config;

import com.getmyuri.gatewayservice.exception.InvalidTokenException;
import com.getmyuri.gatewayservice.service.jwt.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    public static final String HEADER_PREFIX = "Bearer ";

    private final JwtUtil jwtUtil;
    private final ReactiveUserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, ReactiveUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith(HEADER_PREFIX)) {
            String authToken = authHeader.substring(HEADER_PREFIX.length());
            try {
                // No need for initial validateToken(authToken) here as getUsernameFromToken will also parse and validate structure/signature.
                // Expiration is checked by validateToken(authToken, userDetails) or can be checked separately.
                String username = jwtUtil.getUsernameFromToken(authToken); // This can throw JwtException

                if (username != null && ReactiveSecurityContextHolder.getContext().blockOptional().isEmpty()) {
                    return userDetailsService.findByUsername(username)
                        .switchIfEmpty(Mono.defer(() -> {
                            // This case should ideally not be reached if token was valid for a user that no longer exists.
                            // Or if token was for a user that never existed (e.g. manually crafted token)
                            // Depending on policy, could be an error or just proceed without auth.
                            // For strictness, we can consider it an error.
                             return Mono.error(new InvalidTokenException("User for token not found: " + username));
                        }))
                        .flatMap(userDetails -> {
                            if (jwtUtil.validateToken(authToken, userDetails)) { // Checks expiration and username match
                                Authentication authentication = new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                                return chain.filter(exchange)
                                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                            } else {
                                // Token might be for a different user or expired for this specific user check
                                return Mono.error(new InvalidTokenException("Token validation failed for user: " + userDetails.getUsername()));
                            }
                        });
                }
                // If username is null (should not happen if getUsernameFromToken is robust) or context already set, proceed.
                return chain.filter(exchange);

            } catch (ExpiredJwtException e) {
                // Let GlobalExceptionHandler handle this by rethrowing or returning a specific Mono.error
                return Mono.error(new InvalidTokenException("Expired JWT: " + e.getMessage(), e));
            } catch (MalformedJwtException | SignatureException | IllegalArgumentException e) {
                // IllegalArgumentException can be thrown by JJWT for various reasons e.g. empty token string
                return Mono.error(new InvalidTokenException("Invalid JWT: " + e.getMessage(), e));
            } catch (JwtException e) { // Catch-all for other JJWT specific exceptions
                return Mono.error(new InvalidTokenException("JWT processing error: " + e.getMessage(), e));
            }
            // Removed generic Exception catch here to let specific JWT exceptions propagate
            // or to be handled by a global error handler if they are not JWT specific.
        }
        // If no token, proceed without setting authentication
        return chain.filter(exchange);
    }
}
