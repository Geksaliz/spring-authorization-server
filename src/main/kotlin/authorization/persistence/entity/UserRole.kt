package authorization.persistence.entity

import authorization.domain.Role
import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "user_roles")
data class UserRole(
    @field:Id
    @field:GeneratedValue(strategy = GenerationType.UUID)
    private val id: UUID? = null,

    @field:Column(nullable = false)
    private val userId: UUID,
    @field:Column(nullable = false)
    private val role: Role,
)
