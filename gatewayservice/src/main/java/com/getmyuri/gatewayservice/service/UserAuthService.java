package com.getmyuri.gatewayservice.service;

import com.getmyuri.gatewayservice.dto.AuthRequest;
import com.getmyuri.gatewayservice.dto.AuthResponse;
import com.getmyuri.gatewayservice.dto.RefreshTokenRequest;
import com.getmyuri.gatewayservice.exception.InvalidCredentialsException;
import com.getmyuri.gatewayservice.exception.InvalidTokenException;
import com.getmyuri.gatewayservice.exception.TokenRefreshException;
import com.getmyuri.gatewayservice.service.jwt.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class UserAuthService {

    private final ReactiveAuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final ReactiveUserDetailsService userDetailsService; // To get UserDetails for refresh

    public UserAuthService(ReactiveAuthenticationManager authenticationManager,
                           JwtUtil jwtUtil,
                           ReactiveUserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    public Mono<AuthResponse> login(AuthRequest authRequest) {
        Authentication authenticationToken = new UsernamePasswordAuthenticationToken(
                authRequest.getUsername(),
                authRequest.getPassword()
        );

        return this.authenticationManager.authenticate(authenticationToken)
                .flatMap(authentication -> {
                    UserDetails userDetails = (UserDetails) authentication.getPrincipal();
                    String accessToken = jwtUtil.generateAccessToken(userDetails);
                    String refreshToken = jwtUtil.generateRefreshToken(userDetails);
                    return Mono.just(new AuthResponse(accessToken, refreshToken));
                })
                .onErrorResume(AuthenticationException.class, e -> {
                    // Differentiate BadCredentials from other auth issues if needed
                    if (e instanceof BadCredentialsException) {
                        return Mono.error(new InvalidCredentialsException("Invalid username or password."));
                    }
                    return Mono.error(new InvalidCredentialsException("Authentication failed: " + e.getMessage()));
                });
    }

    public Mono<AuthResponse> refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String providedRefreshToken = refreshTokenRequest.getRefreshToken();

        try {
            if (!jwtUtil.validateToken(providedRefreshToken)) {
                // This case might be redundant if validateToken throws an exception handled below
                return Mono.error(new TokenRefreshException(providedRefreshToken, "Refresh token validation failed."));
            }

            String username = jwtUtil.getUsernameFromToken(providedRefreshToken);
            return userDetailsService.findByUsername(username)
                    .switchIfEmpty(Mono.error(new TokenRefreshException(providedRefreshToken, "User not found for refresh token.")))
                    .flatMap(userDetails -> {
                        // Optional: Check if refresh token is revoked or blacklisted in a real scenario
                        String newAccessToken = jwtUtil.generateAccessToken(userDetails);
                        // Optional: Issue a new refresh token as well for enhanced security (refresh token rotation)
                        // String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);
                        // return Mono.just(new AuthResponse(newAccessToken, newRefreshToken));
                        return Mono.just(new AuthResponse(newAccessToken, providedRefreshToken)); // For now, reuse old refresh token
                    });
        } catch (JwtException | IllegalArgumentException e) {
            // Catching common exceptions from jwtUtil.validateToken or getUsernameFromToken
            return Mono.error(new InvalidTokenException("Invalid refresh token: " + e.getMessage(), e));
        }
    }
}
