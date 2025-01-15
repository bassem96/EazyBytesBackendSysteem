package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());*/
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());*/
        http.sessionManagement(var -> var.sessionFixation(session -> session.newSession()).invalidSessionUrl("/invalidSessionUrl").maximumSessions(3).maxSessionsPreventsLogin(true))
                .requiresChannel(var -> var.anyRequest().requiresInsecure()) // http only accepted
                .csrf((csrf) -> csrf.disable())
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
                        .requestMatchers("/notices", "/contact", "/error", "/register").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(var -> var.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(var -> var.accessDeniedHandler(new CustomAccessDeniedHandler()));

        return http.build();
    }


    /*
     * Provides a simple {@link UserDetailsService} that stores a user named "user" with the password "password"
     * and the role "USER". This is sufficient for testing the basic security features.
     *
     * @return a {@link UserDetailsService} that provides a single user.
     */


    /*
     * Provides a default {@link PasswordEncoder} bean.
     * This encoder uses a {@link DelegatingPasswordEncoder} that delegates encoding
     * to other encoders based on a prefix in the password.
     * This ensures compatibility with different password storage formats.
     *
     * @return a {@link PasswordEncoder} instance.
     */


    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Provides a {@link CompromisedPasswordChecker} that delegates to the HaveIBeenPwned API to check if the
     * password has been compromised before.
     *
     * @return a {@link CompromisedPasswordChecker} that checks if the password has been compromised.
     */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
