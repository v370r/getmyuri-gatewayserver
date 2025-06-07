package com.getmyuri.gatewayservice.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-auth-service") // Name used for service discovery (e.g., Eureka)
public interface UserAuthFeignClient {

    /**
     * Calls the user-auth-service to validate the provided authentication token.
     * Assumes the user-auth-service exposes an endpoint at /api/v1/auth/validate
     * that accepts a POST request with a TokenDto and returns:
     * - HTTP 200 OK if the token is valid.
     * - HTTP 401 Unauthorized if the token is invalid or expired.
     *
     * @param tokenDto DTO containing the authentication token.
     * @return ResponseEntity<Void>. HTTP 200 for valid, 401 for invalid.
     */
    @PostMapping("${user-auth-service.endpoints.validate}")
    ResponseEntity<Void> validateToken(@RequestBody TokenDto tokenDto);
}
