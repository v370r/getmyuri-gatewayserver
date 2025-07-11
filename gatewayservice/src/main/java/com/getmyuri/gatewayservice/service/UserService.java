package com.getmyuri.gatewayservice.service;

import com.getmyuri.gatewayservice.dto.User;
import reactor.core.publisher.Mono;

public interface UserService {
    Mono<User> findByUsername(String username);
}
