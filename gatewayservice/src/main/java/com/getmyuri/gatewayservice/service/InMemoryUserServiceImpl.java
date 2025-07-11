package com.getmyuri.gatewayservice.service;

import com.getmyuri.gatewayservice.dto.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; // Will add encoder later
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
public class InMemoryUserServiceImpl implements UserService {

    private final Map<String, User> users = new HashMap<>();

    // Temporary: Password encoder will be properly injected via SecurityConfig later
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostConstruct
    public void init() {
        // Hardcoding a default user for testing purposes
        // In a real application, passwords should be securely encoded and stored.
        // The password here is "password" encoded.
        users.put("user", new User(UUID.randomUUID().toString(),"user", passwordEncoder.encode("password"), Set.of("ROLE_USER")));
        users.put("admin", new User(UUID.randomUUID().toString(),"admin", passwordEncoder.encode("adminpassword"), Set.of("ROLE_ADMIN", "ROLE_USER")));
    }

    @Override
    public Mono<User> findByUsername(String username) {
        User user = users.get(username);
        if (user == null) {
            return Mono.empty();
        }
        return Mono.just(new User(user.getId(), user.getUsername(), user.getPassword(), user.getRoles()));
    }
}
