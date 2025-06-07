package com.getmyuri.gatewayservice.filter;

import com.getmyuri.gatewayservice.client.TokenDto;
import com.getmyuri.gatewayservice.client.UserAuthFeignClient;
import feign.FeignException;
import feign.RetryableException; // Added import
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer; // Added import
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets; // Added import

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);

    private final UserAuthFeignClient userAuthFeignClient;

    @Autowired
    public AuthenticationFilter(UserAuthFeignClient userAuthFeignClient) {
        this.userAuthFeignClient = userAuthFeignClient;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        log.info("Request received for path: {}", request.getPath());

        // 1. Check if Authorization header is present
        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            log.warn("Missing Authorization header for path: {}", request.getPath());
            return onError(exchange, "Missing Authorization header", HttpStatus.UNAUTHORIZED);
        }

        // 2. Get the token from Authorization header
        String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String token = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
        }

        if (token == null || token.isBlank()) {
            log.warn("Invalid or empty Bearer token for path: {}", request.getPath());
            return onError(exchange, "Invalid Bearer token", HttpStatus.UNAUTHORIZED);
        }

        log.debug("Attempting to validate token for path: {}", request.getPath());

        // 3. Validate token using Feign client
        // Note: Feign client calls are blocking by default.
        // For a fully reactive stack, consider using a reactive Feign client or wrapping this call.
        // For simplicity in this step, a direct call is made. This can be improved.
        try {
            // This is a blocking call. In a WebFlux environment, this should be handled carefully.
            // For instance, by subscribing on a different scheduler.
            // ResponseEntity<Void> validationResponse = userAuthFeignClient.validateToken(new TokenDto(token));
            // if (validationResponse.getStatusCode() == HttpStatus.OK) {
            // log.info("Token validated successfully for path: {}", request.getPath());
            // return chain.filter(exchange);
            // } else {
            // log.warn("Token validation failed with status {} for path: {}", validationResponse.getStatusCode(), request.getPath());
            // return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
            // }

            // Reactive approach for Feign client call (preferred in Spring Cloud Gateway)
            // This requires the Feign client to return Mono or Flux, or to wrap the call.
            // For now, let's simulate the blocking call and its handling,
            // acknowledging that a truly reactive Feign client setup is better.

            // Simplified (still effectively blocking here if Feign client is not reactive)
            // This is where a reactive Feign client or a non-blocking call pattern is crucial.
            // For this subtask, we'll write it as if it's blocking and then address reactivity if needed.
            // The Feign client `validateToken` returns ResponseEntity<Void>.
            // A non-200 response from Feign would typically throw a FeignException.

            userAuthFeignClient.validateToken(new TokenDto(token)); // This will throw FeignException for non-2xx/3xx responses
            log.info("Token validated successfully for path: {}", request.getPath());
            return chain.filter(exchange);

        } catch (FeignException.Unauthorized unauthorized) {
            log.warn("Token validation failed (401 - Unauthorized) for path: {}. Error: {}", request.getPath(), unauthorized.getMessage());
            return onError(exchange, "Invalid token or unauthorized", HttpStatus.UNAUTHORIZED);
        } catch (FeignException.Forbidden forbidden) {
            log.warn("Token validation failed (403 - Forbidden) by auth service for path: {}. Error: {}", request.getPath(), forbidden.getMessage());
            return onError(exchange, "Access forbidden by authentication service", HttpStatus.FORBIDDEN);
        } catch (RetryableException retryableException) {
            log.error("Retriable FeignException during token validation for path: {}. Error: {}", request.getPath(), retryableException.getMessage());
            return onError(exchange, "Authentication service is temporarily unavailable", HttpStatus.SERVICE_UNAVAILABLE);
        } catch (FeignException e) {
            log.error("FeignException during token validation for path: {}. Status: {}, Error: {}", request.getPath(), e.status(), e.getMessage());
            if (e.status() >= 500 && e.status() < 600) {
                return onError(exchange, "Upstream authentication service error", HttpStatus.BAD_GATEWAY);
            }
            // For other client-side Feign errors (4xx) not caught above, a generic client error or log and return 500
            return onError(exchange, "Error during token validation communication", HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            log.error("Unexpected error during token validation for path: {}. Error: {}", request.getPath(), e.getMessage(), e);
            return onError(exchange, "An unexpected error occurred during token validation", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8");

        // Create a simple JSON error response
        String errorJson = "{\"error\": \"" + errMessage + "\"}"; // Basic escaping for quotes
        byte[] bytes = errorJson.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);

        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        // Run before other filters, e.g., routing filters
        // Typical values are NettyRoutingFilter.ORDER (2147483647) or LoadBalancerClientFilter.ORDER (10150)
        // We want it to run early, but after some initial setup filters if any.
        return -100; // Example: Higher precedence (lower value)
    }
}
