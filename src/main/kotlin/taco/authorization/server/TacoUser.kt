package taco.authorization.server

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.password.PasswordEncoder
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
data class TacoUser(private var username: String,
                    private var password: String): UserDetails {

    private val roles: MutableList<String> = mutableListOf("ROLE_USER", "ROLE_ADMIN")
    private var role: String = roles[0] // По умолчанию "ROLE_USER"
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private var id: Long = 0

    fun setUsername(name: String) { this.username = name }
    fun setPassword(password: String, encoder: PasswordEncoder) { this.password = encoder.encode(password) }
    fun setRole(rolePosition: Int) { this.role = roles[rolePosition] }
    fun createRole(newRole: String) {
        if (roles.contains(newRole.uppercase())){
            println("Role is already exist")
        } else{
            roles.add(newRole.uppercase())
            println("New role \"${newRole.uppercase()}\" was added")
        }
    }

    override fun getUsername() = username
    override fun getPassword() = password
    fun getRole() = role

    // Пока не предусмотрено отключение пользователей, все функции is... возвращают true
    override fun isAccountNonExpired(): Boolean = true
    override fun isAccountNonLocked(): Boolean = true
    override fun isCredentialsNonExpired(): Boolean = true
    override fun isEnabled(): Boolean = true

    override fun getAuthorities(): List<out GrantedAuthority> {
        return listOf(SimpleGrantedAuthority(role))
    }


}