package taco.authorization.server

import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource


@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeRequests { it.anyRequest().authenticated() }
            .formLogin(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun corsConfigurationSource() : CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        val corConfig = CorsConfiguration().applyPermitDefaultValues().apply {
            allowedOrigins = listOf("yourAllowedOrigin.com", "127.0.0.1")
            allowCredentials = true
            allowedHeaders = listOf("Origin", "Authorization", "Accept", "responseType")
            allowedMethods = listOf("GET", "POST", "PUT", "PATCH", "DELETE")
        }
        source.registerCorsConfiguration("/**", corConfig)
        return source
    }




}