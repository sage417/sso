package app.pooi.sso.ssoserver.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.security.oauth2.authserver.AuthorizationServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class PooiAuthorizationServerConfiguration {

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // todo use rsa
        converter.setSigningKey("pooi_sso");
        return converter;
    }

    @Configuration
    @EnableAuthorizationServer
    @EnableConfigurationProperties(AuthorizationServerProperties.class)
    static class PooiAuthorizationServerConfigurer extends AuthorizationServerConfigurerAdapter {

        private final AuthenticationManager authenticationManager;

        private final TokenStore tokenStore;

        private final AccessTokenConverter tokenConverter;

        private final AuthorizationServerProperties properties;

        public PooiAuthorizationServerConfigurer(
                AuthenticationConfiguration authenticationConfiguration,
                ObjectProvider<TokenStore> tokenStore,
                ObjectProvider<AccessTokenConverter> tokenConverter,
                AuthorizationServerProperties properties) throws Exception {
            this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
            this.tokenStore = tokenStore.getIfAvailable();
            this.tokenConverter = tokenConverter.getIfAvailable();
            this.properties = properties;
        }

        /**
         * Configure the security of the Authorization Server, which means in practical terms the /oauth/token endpoint. The
         * /oauth/authorize endpoint also needs to be secure, but that is a normal user-facing endpoint and should be
         * secured the same way as the rest of your UI, so is not covered here. The default settings cover the most common
         * requirements, following recommendations from the OAuth2 spec, so you don't need to do anything here to get a
         * basic server up and running.
         *
         * @param security a fluent configurer for security features
         */
        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) {
//            security.passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()); // 默认就是这个
            if (this.properties.getCheckTokenAccess() != null) {
                security.checkTokenAccess(this.properties.getCheckTokenAccess());
            }
            if (this.properties.getTokenKeyAccess() != null) {
                security.tokenKeyAccess(this.properties.getTokenKeyAccess());
            }
            if (this.properties.getRealm() != null) {
                security.realm(this.properties.getRealm());
            }
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

            // @formatter:off
            final PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
            clients.inMemory()
                    .withClient("pooi_sso_client_1")
                    .secret(passwordEncoder.encode("pooi_sso_client_1"))
                    .authorizedGrantTypes("authorization_code", "refresh_token")
                    .scopes("all", "read", "write")
                    .autoApprove(true)
                    .and()
                    .withClient("pooi_sso_client_2")
                    .secret(passwordEncoder.encode("pooi_sso_client_2"))
                    .authorizedGrantTypes("authorization_code", "refresh_token")
                    .scopes("all", "read", "write")
                    .autoApprove(true);
            // @formatter:on
        }

        /**
         * Configure the non-security features of the Authorization Server endpoints, like token store, token
         * customizations, user approvals and grant types. You shouldn't need to do anything by default, unless you need
         * password grants, in which case you need to provide an {@link AuthenticationManager}.
         *
         * @param endpoints the endpoints configurer
         */
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            if (this.tokenConverter != null) {
                endpoints.accessTokenConverter(this.tokenConverter);
            }
            if (this.tokenStore != null) {
                endpoints.tokenStore(this.tokenStore);
            }
            endpoints.authenticationManager(this.authenticationManager);
        }
    }
}
