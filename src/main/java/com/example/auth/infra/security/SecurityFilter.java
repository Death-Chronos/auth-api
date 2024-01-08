package com.example.auth.infra.security;

import com.example.auth.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {
    @Autowired
    TokenService tokenService;
    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = this.recoverToken(request); //Pegou o token
        if(token != null){
            var login = tokenService.validateToken(token);
            UserDetails user = userRepository.findByLogin(login);

            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()); //Passa as informações do usuario. como roles e etc para as futuras endpoints(as requisições como /salvar e etc)
            SecurityContextHolder.getContext().setAuthentication(authentication); //Manda pro mano Spring Security
        }
        filterChain.doFilter(request, response); //Chamando o proximo filtro
    }

    private String recoverToken(HttpServletRequest request){ //Função para pegar o token
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null) return null;
        return authHeader.replace("Bearer ", "");
        //É padrão nas requisições um Bearer SEGUIDO do token, o que ela está fazendo é pegar esta palavra e retirando para depois pegar só o token
    }
}
