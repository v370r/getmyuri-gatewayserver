package com.getmyuri.gatewayservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private Mono<ResponseEntity<Map<String, String>>> createErrorResponse(HttpStatus status, String error, String message) {
        Map<String, String> errorDetails = new HashMap<>();
        errorDetails.put("error", error);
        errorDetails.put("message", message);
        return Mono.just(ResponseEntity.status(status).body(errorDetails));
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public Mono<ResponseEntity<Map<String, String>>> handleInvalidCredentialsException(InvalidCredentialsException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid Credentials", ex.getMessage());
    }

    @ExceptionHandler(InvalidTokenException.class)
    public Mono<ResponseEntity<Map<String, String>>> handleInvalidTokenException(InvalidTokenException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid Token", ex.getMessage());
    }

    @ExceptionHandler(TokenRefreshException.class)
    public Mono<ResponseEntity<Map<String, String>>> handleTokenRefreshException(TokenRefreshException ex) {
        return createErrorResponse(HttpStatus.FORBIDDEN, "Token Refresh Error", ex.getMessage());
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public Mono<ResponseEntity<Map<String, String>>> handleUsernameNotFoundException(UsernameNotFoundException ex) {
        // This might be caught by Spring Security earlier, but good to have a handler
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "User Not Found", ex.getMessage());
    }

    @ExceptionHandler(AuthenticationException.class) // Generic Spring Security authentication error
    public Mono<ResponseEntity<Map<String, String>>> handleAuthenticationException(AuthenticationException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Authentication Failed", ex.getMessage());
    }

    @ExceptionHandler(io.jsonwebtoken.ExpiredJwtException.class)
    public Mono<ResponseEntity<Map<String, String>>> handleExpiredJwtException(io.jsonwebtoken.ExpiredJwtException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "JWT Expired", ex.getMessage());
    }

    @ExceptionHandler(io.jsonwebtoken.JwtException.class) // Catches other JJWT specific issues like MalformedJwtException, SignatureException
    public Mono<ResponseEntity<Map<String, String>>> handleJwtException(io.jsonwebtoken.JwtException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid JWT", ex.getMessage());
    }

    // Generic fallback handler
    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, String>>> handleGenericException(Exception ex) {
        // Log the exception here for debugging: ex.printStackTrace(); or use a logger
        System.err.println("Unhandled exception: " + ex.getMessage());
        ex.printStackTrace();
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred. Please try again later.");
    }
}
