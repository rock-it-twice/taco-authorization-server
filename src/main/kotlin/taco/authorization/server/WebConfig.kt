package taco.authorization.server

import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder


@Configuration
class WebConfig {

    @Bean
    fun dataLoader(userRepo: UserRepository, encoder: PasswordEncoder): CommandLineRunner{
        return CommandLineRunner {
            // Создадим 2 тестовых ползователей
            val userAdmin: TacoUser = TacoUser("Habuma", "12345678")
            userAdmin.setRole(1) // присвоим роль админа

            val userAdmin2: TacoUser = TacoUser("TacoChef", "tacotaco")
            userAdmin2.setRole(1) // присвоим роль админа

            // Добавим их в репозиторий
            userRepo.save(userAdmin)
            userRepo.save(userAdmin2)
        }
    }

}