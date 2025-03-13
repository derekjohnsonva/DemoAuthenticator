package com.example.DemoAuthenticator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class DemoAuthenticatorApplication {

  public static void main(String[] args) {
    SpringApplication.run(DemoAuthenticatorApplication.class, args);
  }

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user = User.withUsername("user@example.com")
        .password("{noop}password")
        .roles("ADMIN")
        .build();
    return new InMemoryUserDetailsManager(user);
  }
}
