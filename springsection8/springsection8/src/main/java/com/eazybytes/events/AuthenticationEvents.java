package com.eazybytes.events;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationEvents {

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        log.info("User {} logged in successfully", event.getAuthentication().getName());
    }

    @EventListener
    public void onFail(AbstractAuthenticationFailureEvent event) {
        log.error("User {} failed to log in", event.getAuthentication().getName(), event.getException());
    }
}
