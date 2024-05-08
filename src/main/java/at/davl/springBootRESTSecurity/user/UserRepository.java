package at.davl.springBootRESTSecurity.user;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// JPA all methods is automatic implemented
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
}
