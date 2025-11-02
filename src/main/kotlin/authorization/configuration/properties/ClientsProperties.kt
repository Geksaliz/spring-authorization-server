package authorization.configuration.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("clients")
data class ClientsProperties(
    val tacoClient: ClientProperties
) {
    data class ClientProperties(
        val clientId: String,
        val clientSecret: String,
        val redirectUri: String,
        val postLogoutRedirectUri: String,
        val scopes: Set<String>
    )
}