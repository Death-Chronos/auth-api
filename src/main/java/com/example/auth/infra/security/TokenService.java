package com.example.auth.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.auth.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(User user){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret); //Algoritmo de geração de token( esse secret é definido no applicaton.proprieties normalmente é uma variavel de ambiente)
            String token = JWT.create() //Cria o token
                    .withIssuer("auth-api") //Com o criador
                    .withSubject(user.getLogin()) //Para tal Uber
                    .withExpiresAt(genExpirationDate()) //Tempo de expiração
                    .sign(algorithm); //Com esse algoritmo
            return token;
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating token", exception);
        }
    }

    public String validateToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("auth-api")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException exception){
            return "";
        }
    }

    private Instant genExpirationDate(){
        return LocalDateTime.now() //Pegue a hora atual
                        .plusHours(2) //Adicione duas horas
                        .toInstant(ZoneOffset. //Transforme em um Instant
                        of("-03:00")); //Tirando 3 horas(para ficar igual o horario de Brasilia)
    }
}
