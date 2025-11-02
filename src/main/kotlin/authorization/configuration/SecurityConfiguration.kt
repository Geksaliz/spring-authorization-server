package authorization.configuration

import authorization.configuration.properties.ClientsProperties
import authorization.persistence.repository.UserRepository
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.security.KeyPair
import java.security.KeyPairGenerator

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration
@EnableWebSecurity
class SecurityConfiguration {
    @Value("\${cors.origin.patterns}")
    private val corsOriginPatterns: List<String>? = null

    @Bean
    fun userDetailsService(userRepository: UserRepository): UserDetailsService =
        UserDetailsService { username ->
            userRepository.findByUsername(username)
                .orElseThrow { UsernameNotFoundException("User %s not found".format(username)) }
        }

    @Bean
    fun registeredClientRepository(
        clientsProperties: ClientsProperties,
        passwordEncoder: PasswordEncoder
    ): RegisteredClientRepository {
        val oidcClient: RegisteredClient = RegisteredClient.withId(clientsProperties.tacoClient.clientId)
            .clientId(clientsProperties.tacoClient.clientId)
            .clientSecret(passwordEncoder.encode(clientsProperties.tacoClient.clientSecret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri(clientsProperties.tacoClient.redirectUri)
            .postLogoutRedirectUri(clientsProperties.tacoClient.postLogoutRedirectUri)
            .scopes { it.addAll(clientsProperties.tacoClient.scopes) }
            .scope(OidcScopes.OPENID)
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).requireProofKey(false).build())
            .build()

        return InMemoryRegisteredClientRepository(oidcClient)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()

        http
            .securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .csrf { it.ignoringRequestMatchers(authorizationServerConfigurer.endpointsMatcher) }
            .formLogin(Customizer.withDefaults())
            .apply(authorizationServerConfigurer)

        return http.build()
    }

    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .cors(this::corsConfiguration)
            .formLogin(Customizer.withDefaults())
            .build()
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair: KeyPair = generateRsaKey()
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet: JWKSet = JWKSet(rsaKey)

        return ImmutableJWKSet(jwkSet)
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }

    private fun corsConfiguration(configurer: CorsConfigurer<HttpSecurity?>) =
        configurer.configurationSource(corsConfigurationSource(corsOriginPatterns))

    private fun corsConfigurationSource(originPatterns: List<String>?): CorsConfigurationSource {
        val configuration = CorsConfiguration()
            .apply {
                allowCredentials = true
                allowedOriginPatterns = originPatterns
                allowedHeaders = listOf(CorsConfiguration.ALL)
                exposedHeaders = listOf(CorsConfiguration.ALL)
            }

        return UrlBasedCorsConfigurationSource()
            .apply {
                registerCorsConfiguration("/**", configuration)
            }
    }

    private fun generateRsaKey(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)

        return keyPairGenerator.generateKeyPair()
    }
}