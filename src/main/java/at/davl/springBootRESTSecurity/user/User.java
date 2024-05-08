package at.davl.springBootRESTSecurity.user;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;


// lombok
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
// DB
@Entity
@Table(name = "user_secur")
// implements UserDetails interface -> extend Userdetails
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String firstname;
    private String lastname;

    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // return just 1 role
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        // email will be
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        // change to true
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // change to true
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // change to true
        return true;
    }

    @Override
    public boolean isEnabled() {
        // change to true
        return true;
    }
}
