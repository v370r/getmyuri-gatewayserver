package com.getmyuri.gatewayservice.controller;

import com.getmyuri.gatewayservice.dto.AuthRequest;
import com.getmyuri.gatewayservice.dto.AuthResponse;
import com.getmyuri.gatewayservice.dto.RefreshTokenRequest;
import com.getmyuri.gatewayservice.service.UserAuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody as OpenApiRequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Endpoints for user authentication and token management")
public class AuthController {

    private final UserAuthService userAuthService;

    public AuthController(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @PostMapping("/login")
    @Operation(summary = "User Login",
               description = "Authenticates a user and returns access and refresh tokens.",
               requestBody = @OpenApiRequestBody(content = @Content(mediaType = "application/json",
                                                               schema = @Schema(implementation = AuthRequest.class))),
               responses = {
                   @ApiResponse(responseCode = "200", description = "Authentication successful",
                                content = @Content(mediaType = "application/json",
                                                   schema = @Schema(implementation = AuthResponse.class))),
                   @ApiResponse(responseCode = "401", description = "Invalid credentials",
                                content = @Content)
               })
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest authRequest) {
        return userAuthService.login(authRequest)
                .map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.just(ResponseEntity.status(401).build())); // Basic error handling
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh Access Token",
               description = "Provides a new access token using a valid refresh token.",
               requestBody = @OpenApiRequestBody(content = @Content(mediaType = "application/json",
                                                               schema = @Schema(implementation = RefreshTokenRequest.class))),
               responses = {
                   @ApiResponse(responseCode = "200", description = "Token refresh successful",
                                content = @Content(mediaType = "application/json",
                                                   schema = @Schema(implementation = AuthResponse.class))),
                   @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token",
                                content = @Content)
               })
    public Mono<ResponseEntity<AuthResponse>> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return userAuthService.refreshToken(refreshTokenRequest)
                .map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.just(ResponseEntity.status(401).build())); // Basic error handling
    }
}
