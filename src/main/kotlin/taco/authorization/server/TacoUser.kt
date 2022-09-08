package taco.authorization.server

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
class TacoUser(username: String,
               password: String) : UserDetails {

    private var username = username
    private var password = encodePassword(password)
    private var role: String = "ROLE_ADMIN" // По умолчанию
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private var id: Long = 0

    private fun encodePassword(password: String): String {
        val encoder = BCryptPasswordEncoder()
        return encoder.encode(password).toString()
    }

    fun setRole(role: String) {
        if (role.contains("ROLE_")) this.role = role
        else this.role = "ROLE_${role.uppercase()}"
    }

    override fun getUsername() = username
    override fun getPassword() = password
    fun getRole() = role
    fun getId() = id

    // Пока не предусмотрено отключение пользователей, все функции is... возвращают true
    override fun isAccountNonExpired(): Boolean = true
    override fun isAccountNonLocked(): Boolean = true
    override fun isCredentialsNonExpired(): Boolean = true
    override fun isEnabled(): Boolean = true

    override fun getAuthorities(): List<out GrantedAuthority> {
        return listOf(SimpleGrantedAuthority(role))
    }


}