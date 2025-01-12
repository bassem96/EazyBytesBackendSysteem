package com.eazybytes.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());*/
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());*/
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
                .requestMatchers("/notices", "/contact", "/error").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }


    /*
     * Provides a simple {@link UserDetailsService} that stores a user named "user" with the password "password"
     * and the role "USER". This is sufficient for testing the basic security features.
     *
     * @return a {@link UserDetailsService} that provides a single user.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user =
                User.withUsername("user")
                        .password("{noop}12345")// if we leave it without a prefix it will not work without a password encoder so if want to save it as plain text we need to add {noop} before the password.
                        .roles("USER")
                        .build();

        UserDetails admin = User.withUsername("admin")
                .password("{bcrypt}$2a$12$wGfkGr3adXVZCavqAtjce.bmBBFwV9BG3wDtPklEDSV8oFE0V.xvW")//inorder not to save the plain text in the source code all you have to do is hashing the value and write it down
                // you dont have to mention bcrypt prefix as its the default but will just mention it for better understanding.
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }


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
