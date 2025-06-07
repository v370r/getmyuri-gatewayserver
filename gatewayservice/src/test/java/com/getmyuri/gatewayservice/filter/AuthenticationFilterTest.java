package com.getmyuri.gatewayservice.filter;

import com.getmyuri.gatewayservice.client.TokenDto;
import com.getmyuri.gatewayservice.client.UserAuthFeignClient;
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier; // For testing Mono<Void>

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationFilterTest {

    @Mock
    private UserAuthFeignClient userAuthFeignClient;

    @Mock
    private ServerWebExchange exchange;

    @Mock
    private GatewayFilterChain filterChain;

    @Mock
    private ServerHttpRequest request;

    @Mock
    private ServerHttpResponse response;

    @Mock
    private HttpHeaders headers;

    @InjectMocks
    private AuthenticationFilter authenticationFilter;

    private DefaultDataBufferFactory bufferFactory = new DefaultDataBufferFactory();

    @BeforeEach
    void setUp() {
        when(exchange.getRequest()).thenReturn(request);
        when(exchange.getResponse()).thenReturn(response);
        when(request.getHeaders()).thenReturn(headers);
        // Common setup for response.bufferFactory() used in onError
        when(response.bufferFactory()).thenReturn(bufferFactory);
    }

    private void setupResponseWriteWith() {
        // Capture the buffer written to response
        when(response.writeWith(any())).thenAnswer(invocation -> {
            // In a real test, you might capture and assert the content of the DataBuffer.
            // For now, just completing the Mono to satisfy the method signature.
            return Mono.empty().then();
        });
    }

    // Helper to create a FeignException for testing
    private FeignException createFeignException(int status, String message) {
        return FeignException.errorStatus(message,
            feign.Response.builder()
                .status(status)
                .reason(message)
                .request(Request.create(Request.HttpMethod.POST, "/api/v1/auth/validate", Collections.emptyMap(), null, new RequestTemplate()))
                .headers(Collections.emptyMap())
                .build());
    }

    @Test
    void filter_whenValidToken_shouldProceed() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer validtoken");
        // Mock Feign client to return success (e.g., by not throwing an exception)
        // For ResponseEntity<Void>, a successful call means no exception.
        // If it returned a ResponseEntity, we'd mock: when(userAuthFeignClient.validateToken(any(TokenDto.class))).thenReturn(ResponseEntity.ok().build());
        // Since our Feign client returns void and throws on error, successful call means no mock throwing.
        // We can verify it was called.

        when(filterChain.filter(exchange)).thenReturn(Mono.empty()); // Indicate chain proceeds

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);

        StepVerifier.create(result)
            .verifyComplete(); // Expect the chain to complete normally

        verify(userAuthFeignClient).validateToken(argThat(dto -> "validtoken".equals(dto.getToken())));
        verify(filterChain).filter(exchange); // Verify chain.filter was called
        verify(response, never()).setStatusCode(any(HttpStatus.class)); // Ensure no error status was set
    }

    @Test
    void filter_whenMissingAuthHeader_shouldReturnUnauthorized() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(false);
        setupResponseWriteWith(); // Needed because onError will be called

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);

        StepVerifier.create(result)
            .verifyComplete(); // The response.setComplete() or writeWith() completes the Mono

        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(filterChain, never()).filter(exchange); // Ensure chain.filter was NOT called
    }

    @Test
    void filter_whenTokenInvalid_shouldReturnUnauthorized() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer invalidtoken");

        // Mock Feign client to throw FeignException.Unauthorized
        when(userAuthFeignClient.validateToken(any(TokenDto.class)))
            .thenThrow(FeignException.Unauthorized.errorStatus("validateToken",
                feign.Response.builder()
                    .status(401)
                    .reason("Unauthorized")
                    .request(Request.create(Request.HttpMethod.POST, "/api/v1/auth/validate", Collections.emptyMap(), null, new RequestTemplate()))
                    .headers(Collections.emptyMap())
                    .build())
            );
        setupResponseWriteWith();

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);

        StepVerifier.create(result)
            .verifyComplete();

        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(filterChain, never()).filter(exchange);
    }

    @Test
    void filter_whenAuthServiceReturnsForbidden_shouldReturnForbidden() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer forbiddentoken");
        when(userAuthFeignClient.validateToken(any(TokenDto.class)))
            .thenThrow(createFeignException(403, "Forbidden by auth service"));
        setupResponseWriteWith();

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);
        StepVerifier.create(result).verifyComplete();
        verify(response).setStatusCode(HttpStatus.FORBIDDEN);
    }

    @Test
    void filter_whenAuthServiceRetryableError_shouldReturnServiceUnavailable() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer sometoken");
        when(userAuthFeignClient.validateToken(any(TokenDto.class)))
            .thenThrow(new feign.RetryableException(
                503,
                "Service unavailable",
                Request.HttpMethod.POST,
                null, // cause
                System.currentTimeMillis(),
                Request.create(Request.HttpMethod.POST, "/api/v1/auth/validate", Collections.emptyMap(), null, new RequestTemplate())
            ));
        setupResponseWriteWith();

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);
        StepVerifier.create(result).verifyComplete();
        verify(response).setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void filter_whenAuthServiceReturns5xxError_shouldReturnBadGateway() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer sometoken");
        when(userAuthFeignClient.validateToken(any(TokenDto.class)))
            .thenThrow(createFeignException(500, "Internal Server Error at Auth Service"));
        setupResponseWriteWith();

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);
        StepVerifier.create(result).verifyComplete();
        verify(response).setStatusCode(HttpStatus.BAD_GATEWAY);
    }

    @Test
    void filter_whenMalformedToken_shouldReturnUnauthorized() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer "); // Empty token
        setupResponseWriteWith();

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);
        StepVerifier.create(result).verifyComplete();
        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(filterChain, never()).filter(exchange);
    }

    @Test
    void filter_whenNonBearerToken_shouldReturnUnauthorized() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Basic sometoken"); // Non-Bearer
        setupResponseWriteWith();

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);
        StepVerifier.create(result).verifyComplete();
        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(filterChain, never()).filter(exchange);
    }

    @Test
    void filter_whenAuthServiceUnexpectedException_shouldReturnInternalServerError() {
        when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer sometoken");
        when(userAuthFeignClient.validateToken(any(TokenDto.class)))
            .thenThrow(new RuntimeException("Unexpected chaos"));
        setupResponseWriteWith();

        Mono<Void> result = authenticationFilter.filter(exchange, filterChain);
        StepVerifier.create(result).verifyComplete();
        verify(response).setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // TODO: Test for order of the filter if necessary, though getOrder() is simple.
    // TODO: Test the content of the JSON error response if more complex.
}
