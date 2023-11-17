//package com.lsitc.domain;
//
//import com.lsitc.global.jwt.JwtTokenProvider;
//import io.jsonwebtoken.JwtParser;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.io.Decoders;
//import io.jsonwebtoken.security.Keys;
//import lombok.extern.slf4j.Slf4j;
//import org.junit.jupiter.api.Disabled;
//import org.junit.jupiter.api.Test;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.context.SecurityContextHolder;
//
//import java.security.Key;
//import java.util.ArrayList;
//import java.util.Date;
//import java.util.List;
//
//@Slf4j
//@SpringBootTest
//class ApplicationTests {
//
//	@Test
//	@Disabled
//	void contextLoads() {
//
//
//		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
//				"test",
//				"test"
//		);
//
////		AuthenticationManagerBuilder authenticationManagerBuilder = null;
////
////		Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
////		SecurityContextHolder.getContext().setAuthentication(authentication);
//
//		String secret = "bHNtZXNfMjAyM19wcm9qZWN0XzAxMjM0NTY3ODlfMDEyMzQ1Njc4OV8wMTIzNDU2Nzg5XzAxMjM0NTY3ODlfMDEyMzQ1Njc4OQ";
//		long tokenValidityInMilliseconds = 600000000;
//
//		//시크릿 값을 decode해서 키 변수에 할당
//		byte[] keyBytes = Decoders.BASE64.decode(secret);//Base64Utils.decodeFromString(secret);
//		Key key = Keys.hmacShaKeyFor(keyBytes);
//		JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
//
//		long now = (new Date()).getTime();
//		Date validity = new Date(now + tokenValidityInMilliseconds);
//
//		String jwt =  Jwts.builder()
//				.setSubject("admin")
//				.claim("auth", null)
//				.signWith(key, SignatureAlgorithm.HS512)
//				.setExpiration(validity)
//				.compact();
//
//
//		log.error("jwt={}",jwt);
//
//		jwtParser.parseClaimsJws(jwt);
//		//Claims claims = (Claims) jwtParser.setSigningKey(key).parseClaimsJws(jwt);
//
//		String body = String.valueOf(Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody());
//	}
//
//	@Test
//	void test2(){
//
//		AuthenticationManager authenticationManager = new AuthenticationManager() {
//
//			@Override
//			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//				return new UsernamePasswordAuthenticationToken("admin","password");
//			}
//
//		};
//
//		String secret = "bHNtZXNfMjAyM19wcm9qZWN0XzAxMjM0NTY3ODlfMDEyMzQ1Njc4OV8wMTIzNDU2Nzg5XzAxMjM0NTY3ODlfMDEyMzQ1Njc4OQ";
//		long tokenValidityInMilliseconds = 600000000;
//
//		JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(secret,tokenValidityInMilliseconds);
//
//		Authentication authentication =authenticationManager.authenticate(null);
//
//		String jwt = jwtTokenProvider.createToken(authentication);
//
//		log.error("jwt={}",jwt);
//	}
//
//}
