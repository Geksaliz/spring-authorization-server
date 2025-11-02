package authorization.persistence.entity

import authorization.domain.Role
import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.UUID

@Entity
@Table(name = "users")
data class User(
    @field:Id
    @field:GeneratedValue(strategy = GenerationType.UUID)
    private val id: UUID? = null,

    @field:Column(nullable = false, unique = true)
    private val username: String = "",

    @field:Column(nullable = false)
    private val password: String = "",

    @field:Column(nullable = true)
    private val fullName: String? = null,
    @field:Column(nullable = true)
    private val street: String? = null,
    @field:Column(nullable = true)
    private val city: String? = null,
    @field:Column(nullable = true)
    private val state: String? = null,
    @field:Column(nullable = true)
    private val zip: String? = null,
    @field:Column(nullable = true)
    private val phoneNumber: String? = null,

    @field:ElementCollection(fetch = FetchType.EAGER)
    @field:CollectionTable(name = "user_roles", joinColumns = [JoinColumn(name = "userId")])
    @field:Column(name = "role")
    private val roles: Set<Role> = setOf(),
) : UserDetails {

    override fun getAuthorities(): Collection<GrantedAuthority> =
        roles.map { SimpleGrantedAuthority(it.name) }

    override fun getPassword(): String = password

    override fun getUsername(): String = username

    fun getId(): UUID? = id
}
