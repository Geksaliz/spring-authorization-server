package authorization.configuration

import authorization.domain.Role
import authorization.persistence.entity.User
import authorization.persistence.entity.UserRole
import authorization.persistence.repository.UserRepository
import authorization.persistence.repository.UserRoleRepository
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
class UserDataLoader {

    @Bean
    fun dataLoader(
        userRepository: UserRepository,
        userRoleRepository: UserRoleRepository,
        encoder: PasswordEncoder,
    ): ApplicationRunner {
        return ApplicationRunner {
            userRepository.save(
                User(
                    username = "koleso",
                    password = encoder.encode("123") ?: "empty"
                )
            ).getId()?.let {
                userRoleRepository.save(UserRole(
                    userId = it,
                    role = Role.ROLE_ADMIN,
                ))
            }


            userRepository.save(
                User(
                    username = "user",
                    password = encoder.encode("123") ?: "empty"
                )
            ).getId()?.let {
                userRoleRepository.save(UserRole(
                    userId = it,
                    role = Role.ROLE_USER,
                ))
            }
        }
    }
}