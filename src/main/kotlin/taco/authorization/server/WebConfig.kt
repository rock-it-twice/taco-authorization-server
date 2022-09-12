package taco.authorization.server

import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration


@Configuration
class WebConfig {

    @Bean
    fun dataLoader(userRepo: UserRepository): CommandLineRunner{
        return CommandLineRunner {
            // Создадим 3 тестовых ползователей
            val userAdmin: TacoUser = TacoUser("Habuma", "password")
            val userAdmin2: TacoUser = TacoUser("tacochef", "password")
            // Добавим их в репозиторий
            userRepo.save(userAdmin)
            userRepo.save(userAdmin2)
        }
    }

}