package com.getmyuri.gatewayservice.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouterValidator {

    private static final Logger logger = LoggerFactory.getLogger(RouterValidator.class);

    public static final List<String> openApiEndpoints = List.of(
            "/userauth/register",
            "/userauth/token",
            "/eureka"
    );

    public Predicate<ServerHttpRequest> isSecured =
            request -> {
                boolean secured = openApiEndpoints
                        .stream()
                        .noneMatch(uri -> request.getURI().getPath().contains(uri));
                logger.info("Request URI: " + request.getURI().getPath() + ", isSecured: " + secured);
                return secured;
            };

}
