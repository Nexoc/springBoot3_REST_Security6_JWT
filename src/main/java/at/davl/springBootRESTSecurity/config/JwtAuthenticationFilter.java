package at.davl.springBootRESTSecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor // create constructor of any final fields that is used
// extends OncePerRequestFilter -> every request
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(
            // All parameters should be annotated @NonNull
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain // chain. It contains all method, that we have to execute
            ) throws ServletException, IOException {

        // Bearer Token
        // 2 Hours to fix Authorisation to Authorization!!!
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // if header null or if this auth start not with "Bearer " -> then return (stop)
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7); // "Bearer " -> 6 + 1 space
        userEmail = jwtService.extractUsername(jwt); // extract the userEmail from JWT token

        // if email not null and user not authenticated
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // load user from DB
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // if token valid
            if(jwtService.isTokenValid(jwt, userDetails)) {
                // create new auth Token
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        // more details of user
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // update security auth token
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }
        }
        // FILTER
        filterChain.doFilter(request, response);
    }
}
