package com.blws.global.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.blws.domain.common.auth.vo.AuthFailureGetRequestVO;
import com.blws.domain.common.auth.vo.AuthSuccessGetResponseVO;
import com.blws.domain.common.user.dao.UserDAO;
import com.blws.domain.common.user.entity.UserEntity;
import com.blws.domain.common.user.service.UserService;
import com.blws.domain.common.user.vo.UserInfoGetRequestVO;
import com.blws.global.jwt.management.SecurityMetersService;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JWTTokenProvider {

    private static final String AUTHORITIES_KEY = "auth";

    private static final String INVALID_JWT_TOKEN = "Invalid JWT token.";

    public static final String AUTHORIZATION_ACCESS_HEADER = "authorization";

    public static final String AUTHORIZATION_ACCESS_TOKEN = "accessToken";

    public static final String AUTHORIZATION_REFRESH_TOKEN = "refreshToken";


    private final Key key;

    private final JwtParser jwtParser;

    private final long tokenAccessValidityInSeconds;
    private final long tokenRefreshValidityInSeconds;
    private final int tokenAccessCookieMaxAge;
    private final int tokenRefreshCookieMaxAge;

    private final SecurityMetersService securityMetersService;

    private final UserService userService;
    private final UserDAO userDAO;

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public JWTTokenProvider(@Value("${spring.jwt.secret}") String secret,
                            @Value("${spring.jwt.token-access-validity-in-seconds}") long tokenAccessValidityInSeconds,
                            @Value("${spring.jwt.token-refresh-validity-in-seconds}") long tokenRefreshValidityInSeconds,
                            SecurityMetersService securityMetersService, UserService userService, UserDAO userDAO, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.userService = userService;
        this.userDAO = userDAO;
        this.securityMetersService = securityMetersService;

        this.authenticationManagerBuilder = authenticationManagerBuilder;

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        jwtParser = Jwts.parserBuilder().setSigningKey(key).build();

        this.tokenAccessValidityInSeconds = 1000 * tokenAccessValidityInSeconds;
        this.tokenRefreshValidityInSeconds = 1000 * tokenRefreshValidityInSeconds;

        this.tokenAccessCookieMaxAge= (int) tokenAccessValidityInSeconds;
        this.tokenRefreshCookieMaxAge= (int) tokenRefreshValidityInSeconds;
    }

    public String createAccessToken(Authentication authentication) {

        String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenAccessValidityInSeconds);

        return Jwts
                .builder()
                .setId(authentication.getName())
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    public String createRefreshToken(Authentication authentication) {

        String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenRefreshValidityInSeconds);

        return Jwts
                .builder()
                .setId(authentication.getName())
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = jwtParser.parseClaimsJws(token).getBody();

        Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .filter(auth -> !auth.trim().isEmpty())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean validateToken(String authToken) {
        try {

            jwtParser.parseClaimsJws(authToken);

            return true;
        }
//        catch (ExpiredJwtException e) {
//            this.securityMetersService.trackTokenExpired();
//
//            log.trace(INVALID_JWT_TOKEN, e);
//        }
        catch (UnsupportedJwtException e) {
            this.securityMetersService.trackTokenUnsupported();

            log.trace(INVALID_JWT_TOKEN, e);
        } catch (MalformedJwtException e) {
            this.securityMetersService.trackTokenMalformed();

            log.trace(INVALID_JWT_TOKEN, e);
        } catch (SignatureException e) {
            this.securityMetersService.trackTokenInvalidSignature();

            log.trace(INVALID_JWT_TOKEN, e);
        } catch (IllegalArgumentException e) { // TODO: should we let it bubble (no catch), to avoid defensive programming and follow the fail-fast principle?
            log.error("Token validation error {}", e.getMessage());
        }

        return false;
    }

    public String resolveAccessToken(HttpServletRequest request) {

        String bearerToken = request.getHeader(AUTHORIZATION_ACCESS_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        String jwt = request.getParameter(AUTHORIZATION_ACCESS_TOKEN);
        if (StringUtils.hasText(jwt)) {
            return jwt;
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> this.AUTHORIZATION_ACCESS_TOKEN.equals(cookie.getName()))
                .findFirst()
                .orElse(null)
                .getValue();
    }


    public String resolveRefreshToken(HttpServletRequest request) {
        return Arrays.stream(request.getCookies())
                .filter(cookie -> this.AUTHORIZATION_REFRESH_TOKEN.equals(cookie.getName()))
                .findFirst()
                .orElse(null)
                .getValue();
    }


    public Boolean checkAccessToken(ServletRequest servletRequest, ServletResponse servletResponse) {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String accessToken = this.resolveAccessToken(httpServletRequest);
        String refreshToken = this.resolveRefreshToken(httpServletRequest);

        String userId = jwtParser.parseClaimsJws(accessToken).getBody().getId();

        UserEntity userEntity = userDAO.selectUserByUserId(UserInfoGetRequestVO.builder()
                .userId(userId)
                .build().toEntity());

        if( !(userEntity.getAccessToken().equals(accessToken) && userEntity.getRefreshToken().equals(refreshToken)) ){
            return false;
        }

        if (StringUtils.hasText(accessToken) && this.validateToken(accessToken)
                && StringUtils.hasText(refreshToken) && this.validateToken(refreshToken)) {

            Date expirationDate = jwtParser.parseClaimsJws(accessToken).getBody().getExpiration();

            if(expirationDate.before(new Date())){
                this.setCookieAndSetToken(this.getAuthentication(accessToken),(HttpServletResponse) servletResponse);
            }else{
                Authentication authentication = this.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            return true;

        }

        return false;
    }

    public AuthSuccessGetResponseVO signIn(AuthFailureGetRequestVO loginVM, HttpServletResponse httpServletResponse){

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginVM.getUserId(),
                loginVM.getPassword()
        );

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        this.setCookieAndSetToken(authentication,httpServletResponse);

        return AuthSuccessGetResponseVO.of((UserEntity) SecurityContextHolder.getContext().getAuthentication().getPrincipal());

    }

    public void signOut(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {

        this.removeJwtCookies(httpServletResponse);

        try {
            String accessToken = this.resolveAccessToken(httpServletRequest);
            String refreshToken = this.resolveAccessToken(httpServletRequest);
            String userId = "";


            if(StringUtils.hasText(accessToken) || StringUtils.hasText(refreshToken)){
               userId = jwtParser.parseClaimsJws(StringUtils.hasText(accessToken) ? accessToken : refreshToken).getBody().getId();
            }

            Authentication authentication = this.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            userService.updateUserToken(UserEntity.builder()
                    .userId(userId)
                    .accessToken(null)
                    .refreshToken(null)
                    .build());

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    private void setCookieAndSetToken(Authentication authentication,HttpServletResponse httpServletResponse){

        try {
            String accessToken = this.createAccessToken(authentication);
            String refreshToken = this.createRefreshToken(authentication);

            this.setJwtCookies(accessToken, refreshToken, httpServletResponse);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String userId = jwtParser.parseClaimsJws(accessToken).getBody().getId();

            UserEntity userEntity = UserEntity.builder()
                    .userId(userId)
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();

            userService.updateUserToken(userEntity);

        }catch (Exception e){
            throw new SignatureException(e.getMessage());
        }

    }

    private void setJwtCookies(String accessToken, String refreshToken, HttpServletResponse httpServletResponse) throws UnsupportedEncodingException {

        httpServletResponse.addHeader(this.AUTHORIZATION_ACCESS_HEADER, "Bearer " + accessToken);

        Cookie accessTokenCookie = new Cookie(AUTHORIZATION_ACCESS_TOKEN,URLEncoder.encode(accessToken,"UTF-8"));
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(this.tokenAccessCookieMaxAge);

        ResponseCookie refreshTokenCookie = ResponseCookie.from(AUTHORIZATION_REFRESH_TOKEN, URLEncoder.encode(refreshToken,"UTF-8"))
                .path("/")
//                .sameSite("None")
                .httpOnly(false)
                .secure(false)
                .maxAge(this.tokenAccessCookieMaxAge)
                .build();

        httpServletResponse.addHeader("Set-Cookie",refreshTokenCookie.toString());
        httpServletResponse.addCookie(accessTokenCookie);

    }

    private void removeJwtCookies(HttpServletResponse httpServletResponse){
        try {
            httpServletResponse.addHeader(this.AUTHORIZATION_ACCESS_HEADER,null);

            Cookie refreshTokenCookie = new Cookie(AUTHORIZATION_ACCESS_TOKEN, null);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(0);

            Cookie accessTokenCookie = new Cookie(AUTHORIZATION_REFRESH_TOKEN,null);
            accessTokenCookie.setPath("/");
            accessTokenCookie.setMaxAge(0);

            httpServletResponse.addCookie(refreshTokenCookie);
            httpServletResponse.addCookie(accessTokenCookie);
        }catch (Exception e){
            throw new SignatureException(e.getMessage());
        }

    }
}