package com.example.DemoAuthenticator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

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

  @Configuration
  @EnableWebSecurity
  public class AuthServerConfig {

    // Register Okta as a client in the Spring Boot IdP
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
      RegisteredClient oktaClient = RegisteredClient.withId(UUID.randomUUID().toString())
          .clientId("okta-client") // Match Okta SP configuration
          .clientSecret("{noop}okta-client-secret") // Use proper
                                                    // encryption in
                                                    // production
          .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // Changed this in order to use a
                                                                                     // different auth thing
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .redirectUri("https://dev-50824006.okta.com/oauth2/v1/authorize/callback") // Okta's ACS URL
          .scope(OidcScopes.OPENID)
          .scope(OidcScopes.PROFILE)
          .scope(OidcScopes.EMAIL)
          .clientSettings(ClientSettings.builder()
              .requireAuthorizationConsent(true)
              .build())
          .build();

      return new InMemoryRegisteredClientRepository(oktaClient);
    }

    // Configure JWK for token signing
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
      KeyPair keyPair = generateRsaKey();
      RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
      RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
      RSAKey rsaKey = new RSAKey.Builder(publicKey)
          .privateKey(privateKey)
          .keyID(UUID.randomUUID().toString())
          .build();

      Logger logger = LoggerFactory.getLogger(AuthServerConfig.class);
      logger.debug("Generated RSA Public Key: {}", rsaKey.toPublicJWK().toJSONString());
      logger.debug("Generated RSA Private Key: {}", rsaKey.toJSONString());
      JWKSet jwkSet = new JWKSet(rsaKey);
      return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
      KeyPair keyPair;
      try {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
      } catch (Exception ex) {
        throw new IllegalStateException(ex);
      }
      return keyPair;
    }

    // Expose OIDC endpoints
    // @Bean
    // @Order(Ordered.HIGHEST_PRECEDENCE)
    // public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http)
    // throws Exception {
    // OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    // return http.formLogin(Customizer.withDefaults()).build();
    // }
  }

}
