package at.davl.springBootRESTSecurity.auth;

import at.davl.springBootRESTSecurity.config.JwtService;
import at.davl.springBootRESTSecurity.user.Role;
import at.davl.springBootRESTSecurity.user.User;
import at.davl.springBootRESTSecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // This Method allows us to get User, SAVE User in DB and return generated token
    public AuthenticationResponse register(RegisterRequest request){

        // create user from Data that we get from request
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                // decode password
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        // save user in DB
        repository.save(user);
        // generate token
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                // add token to this response
                .token(jwtToken)
                .build();
    }

    // check if user is authenticated, if not, auth him and give him a  new token
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        // check if user is authenticated
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // if user not authenticated, check in DB if this User exist:
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        // generate token
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                // add token to this response
                .token(jwtToken)
                .build();

    }

}
