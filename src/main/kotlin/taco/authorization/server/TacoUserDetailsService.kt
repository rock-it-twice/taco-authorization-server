package taco.authorization.server

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

@Service
class TacoUserDetailsService(private val userRepo: UserRepository) : UserDetailsService {

        override fun loadUserByUsername(username: String): UserDetails {
            val tacoUser: TacoUser = userRepo.findByUsername(username)!!
            val authorities = listOf<GrantedAuthority>(SimpleGrantedAuthority(tacoUser.getRole()))
            return User(tacoUser.getId().toString(), tacoUser.password, tacoUser.authorities)
        }

}
