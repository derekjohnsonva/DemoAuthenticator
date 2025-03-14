package com.example.DemoAuthenticator.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.example.DemoAuthenticator.service.OidcUserInfoService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

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

  @Configuration
  public class IdTokenCustomizerConfig {
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
        OidcUserInfoService userInfoService) {
      return (context) -> {
        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
          OidcUserInfo userInfo = userInfoService.loadUser(
              context.getPrincipal().getName());
          context.getClaims().claims(claims -> claims.putAll(userInfo.getClaims()));
        }
      };
    }
  }

  // This is the base http security info for the Oauth2 Auth Server
  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer
        .authorizationServer();
    http
        .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
        .with(authorizationServerConfigurer, (authServer) -> authServer.oidc(Customizer.withDefaults()))
        .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
    http
        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        .exceptionHandling((exceptions) -> exceptions
            .authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")))
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));

    return http.build();
  }

  // This is here in order to get our custom login page.
  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated())
        // Form login handles the redirect to the login page from the
        // authorization server filter chain
        .formLogin((formLogin) -> formLogin
            .loginPage("/login")
            .permitAll());
    return http.build();
  }

}
