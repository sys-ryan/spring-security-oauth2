package com.example.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ClientConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                        .requestMatchers("/home", "/login").permitAll()
                        .anyRequest().authenticated()
        );
        http.oauth2Login(authLogin -> authLogin.authorizationEndpoint(authEndpoint -> authEndpoint.authorizationRequestResolver(customOAuth2AuthorizationRequestResolver())));
        http.logout(logout -> logout.logoutSuccessUrl("/home"));

        return http.build();
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }
}
