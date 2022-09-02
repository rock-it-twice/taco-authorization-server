package taco.authorization.server

import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain


@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeRequests { it.anyRequest().authenticated() }
            .formLogin()
        return http.build()
    }

    @Bean
    fun userDetailsServer(userRepo: UserRepository): (String) -> UserDetails {
        return { username: String ->
            userRepo.findByUsername(username) ?: throw UsernameNotFoundException("User: $username not found") }
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

}