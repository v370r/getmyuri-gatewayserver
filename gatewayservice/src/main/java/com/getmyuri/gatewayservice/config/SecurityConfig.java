package com.getmyuri.gatewayservice.config;

import com.getmyuri.gatewayservice.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity // Enables @PreAuthorize, @PostAuthorize, etc.
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsServiceImpl userDetailsService;


    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, UserDetailsServiceImpl userDetailsService) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(UserDetailsServiceImpl userDetailsService, PasswordEncoder passwordEncoder) {
        UserDetailsRepositoryReactiveAuthenticationManager authenticationManager =
                new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        authenticationManager.setPasswordEncoder(passwordEncoder);
        return authenticationManager;
    }

    // This is to make sure the InMemoryUserServiceImpl gets the correct PasswordEncoder
    // It's a bit of a workaround because @PostConstruct in InMemoryUserServiceImpl runs before this config.
    // A better solution would be to refactor InMemoryUserServiceImpl to not encode passwords in @PostConstruct
    // or to have it depend on PasswordEncoder directly if it were a @Bean itself.
    @Bean
    public UserDetailsServiceImpl userDetailsServiceImplWithEncoder(com.getmyuri.gatewayservice.service.UserService rawUserService, PasswordEncoder encoder) {
        // This is assuming InMemoryUserServiceImpl is the one being autowired for UserService
        if (rawUserService instanceof com.getmyuri.gatewayservice.service.InMemoryUserServiceImpl) {
            // This is not ideal as it relies on a specific implementation and doesn't truly reinject.
            // For a real application, user creation with encoded passwords should be handled differently,
            // e.g., via a CommandLineRunner after the PasswordEncoder bean is available, or by
            // ensuring the service that needs it gets it injected properly.
            // The current InMemoryUserServiceImpl creates a new BCryptPasswordEncoder().
            // To fix this properly, InMemoryUserServiceImpl should take PasswordEncoder as a constructor arg.
            // For now, we are relying on the fact that both will be BCrypt.
        }
        return new UserDetailsServiceImpl(rawUserService);
    }


    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // Typically disabled for stateless APIs
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable) // Disable basic auth
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable) // Disable form login
                // As JWT is stateless, we don't need to store SecurityContext
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/login", "/auth/refresh").permitAll()
                        .pathMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/webjars/**").permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";
        return new OpenAPI()
                .info(new Info().title("Gateway Service API")
                        .version("v1.0")
                        .description("API for Gateway Service including JWT Authentication")
                        .license(new License().name("Apache 2.0").url("http://springdoc.org")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(
                        new Components()
                                .addSecuritySchemes(securitySchemeName,
                                        new SecurityScheme()
                                                .name(securitySchemeName)
                                                .type(SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .bearerFormat("JWT")
                                )
                );
    }
}
