package authorization.persistence.repository;

import authorization.persistence.entity.UserRole
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.UUID

@Repository
interface UserRoleRepository : JpaRepository<UserRole, UUID> {
}