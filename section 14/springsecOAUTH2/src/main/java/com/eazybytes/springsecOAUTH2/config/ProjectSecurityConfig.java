package com.eazybytes.springsecOAUTH2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecuirtyFilterChain(HttpSecurity httpsecurity) throws Exception {
        httpsecurity.authorizeHttpRequests((requests) -> requests.requestMatchers("/secure").authenticated().anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults()); // Add this line

        return httpsecurity.build();
    }


    /*
    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration github = gitHubClientRegistration();
        ClientRegistration facebook = facebookClientRegistration();
        return new InMemoryClientRegistrationRepository(github, facebook);
    }

    private ClientRegistration gitHubClientRegistration() {
        return CommonOAuth2Provider.GITHUB.getBuilder("github").clientId("Ov23li2l2hmHHin75NCQ").clientSecret("78c64513569ab598045020fe4ffced99d987bed2").build();
    }

    private ClientRegistration facebookClientRegistration() {
        return CommonOAuth2Provider.FACEBOOK.getBuilder("facebook").clientId("2099054223919612").clientSecret("5c767b9f6dbb9763dfa719f8d3a1480c").build();
    }

   */
}

