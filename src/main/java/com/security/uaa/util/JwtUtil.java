package com.security.uaa.util;

import com.security.uaa.domain.Role;
import com.security.uaa.domain.User;
import com.security.uaa.resource.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component

public class JwtUtil {

    public static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512); // 用于签名 Access Token

    public static final Key refreshKey = Keys.secretKeyFor(SignatureAlgorithm.HS512); // 用于签名 Refresh Token

    @Autowired
    private AppProperties appProperties;

    /**
     * 根据用户信息生成一个 JWT
     *
     * @param userDetails  用户信息
     * @param timeToExpire 毫秒单位的失效时间
     * @param signKey      签名使用的 key
     * @return JWT
     */
    public String createJwtToken(UserDetails userDetails, long timeToExpire, Key signKey){

        var now = System.currentTimeMillis();

        return Jwts.builder()
                .setId("mooc")
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(now + timeToExpire))
                .signWith(signKey, SignatureAlgorithm.HS512)
                .claim("authorities",userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
                )
                .compact();
    }

    public String createAccessToken(UserDetails userDetails){
        return createJwtToken(userDetails, appProperties.getJwt().getAccessTokenExpireTime(), key);
    }

    public String createRefreshToken(UserDetails userDetails){
        return createJwtToken(userDetails, appProperties.getJwt().getRefreshTokenExpireTime(), refreshKey);
    }

    public Optional<Claims> parseClaims(String token, Key key){
        try {
            var body = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            return Optional.of(body);
        }catch (Exception e){
            return Optional.empty();
        }
    }

    public static void main(String[] args) {

        var username = "user";
        var authorities = Set.of(
                Role
                        .builder()
                        .authority(Constants.ROLE_USER)
                        .build(),
                Role
                        .builder()
                        .authority(Constants.ROLE_ADMIN)
                        .build()
        );

        var user = User.builder()
                .username(username)
                .authorities(authorities)
                .build();
        var token = new JwtUtil().createAccessToken(user);

        System.out.println(token);

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(JwtUtil.key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        System.out.println(claims);
        List<?> list = CollectionUtil.convertObjectToList(claims.get("authorities"));

        System.out.println(list);

    }





}
