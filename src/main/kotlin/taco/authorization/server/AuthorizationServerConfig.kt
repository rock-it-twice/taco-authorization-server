package taco.authorization.server

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ClientSettings
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.web.SecurityFilterChain

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration

import java.util.UUID



@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // Задается приоритет над другими Bean того же типа
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        // репозиторий клиентов
        // (хранит сведения о клиентах, которые могут запрашивать авторизацию от имени пользователей)
        OAuth2AuthorizationServerConfiguration
            .applyDefaultSecurity(http.cors().and())

        http
            .cors()
            .and()
            .csrf()
            .disable()
            .formLogin(withDefaults<FormLoginConfigurer<HttpSecurity>>())
        return http.build()
    }

    @Bean
    fun registeredClientRepository(passwordEncoder: PasswordEncoder): RegisteredClientRepository {

        val clientId = "taco-admin-client"
        val clientSecret = "secret"

        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(5))
                    .refreshTokenTimeToLive(Duration.ofMinutes(10))
                    .build()
            )
            .clientId( clientId )
            .clientSecret(passwordEncoder.encode( clientSecret ))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://127.0.0.1:9090/login/oauth2/code/taco-admin-client")
            .redirectUri("https://oauth.pstmn.io/v1/callback")
            .scope("writeIngredients")
            .scope("deleteIngredients")
            .scope(OidcScopes.OPENID)
            .clientSettings(
                ClientSettings
                    .builder()
                    .requireAuthorizationConsent(true)
                    .build()
            )
            .build()

        return InMemoryRegisteredClientRepository(listOf(registeredClient))
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> = runCatching {
        val rsaKey: RSAKey = KeyGeneratorUtils.generateRsaKey()
        val jwkSet = JWKSet(rsaKey)
        return@runCatching JWKSource<SecurityContext> { jwkSelector, _ -> jwkSelector.select(jwkSet) }
    }.getOrElse { exception -> throw NoSuchAlgorithmException(exception) }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder{
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun providerSettings(): ProviderSettings {
        val issuerUrl = "http://127.0.0.1:9000"
        return ProviderSettings.builder().issuer(issuerUrl).build()
    }


}