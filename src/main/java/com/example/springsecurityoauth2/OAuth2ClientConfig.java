package com.example.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ClientConfig {

//    @Autowired
//    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests

                        .requestMatchers("/home", "/client").permitAll()

                        .anyRequest().authenticated()
        )
                .oauth2Client(Customizer.withDefaults())

                ;

        http.logout(logout -> logout.logoutSuccessUrl("/home"));
        return http.build();
    }
}
