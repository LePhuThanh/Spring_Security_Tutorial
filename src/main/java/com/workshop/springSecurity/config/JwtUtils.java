package com.workshop.springSecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

//JwtUtils class handle the JWT

@Component
public class JwtUtils {
    //Claim is information & data user is saved into token
    private String jwtSigningKey = "secret";
    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .setSigningKey(jwtSigningKey)
                .parseClaimsJwt(token)
                .getBody();
    }
    // to extract specifically a claim
    //claimsResolver is lambda expression that We can pass to determine the type of information to extract
    //EXP: Claims::getSubject to get subject
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    //To check that Does JWT include claim?
    public boolean hasClaim(String token, String claimName) {
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) != null;
    }
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); //belong to JWT library // includes information
    }
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    //generates a JWT for a user without adding any custom claims
    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails);
    }
    //Add custom information to JWT
    public String generateToken(UserDetails userDetails, Map<String, Object> claims){
        return createToken(claims, userDetails);
    }
    //This method generates the JWT using information from claims and UserDetails
    private String createToken(Map<String, Object> claims, UserDetails userDetails){
        return Jwts.builder().setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24)))
                .signWith(SignatureAlgorithm.HS256, jwtSigningKey).compact();
    }
    public Boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && ! isTokenExpired(token));
        //To check the username from the JWT & username from the userDetails AND JWT is expired or not
    }

}
