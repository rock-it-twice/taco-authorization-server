package taco.authorization.server


import org.springframework.data.repository.CrudRepository


interface UserRepository: CrudRepository<TacoUser, String> {
    fun findByUsername(username: String): TacoUser?

}