package com.blws.global.jwt;

import com.blws.global.error.ErrorResponse;
import com.blws.global.error.exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTFilter extends GenericFilterBean {

    private final JWTTokenProvider jWTTokenProvider;

    public JWTFilter(JWTTokenProvider jWTTokenProvider) {
        this.jWTTokenProvider = jWTTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        try {

            if(!this.jWTTokenProvider.checkAccessToken(servletRequest,servletResponse)){
                this.setErrorResponse(HttpStatus.UNAUTHORIZED,(HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse);
            }

            filterChain.doFilter(servletRequest, servletResponse);

        }catch (Exception e){
            this.setErrorResponse(HttpStatus.UNAUTHORIZED, (HttpServletRequest) servletRequest, (HttpServletResponse)servletResponse);
        }

    }

    public void setErrorResponse(HttpStatus status, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse){

        try{

            ObjectMapper objectMapper = new ObjectMapper();
            httpServletResponse.setStatus(status.value());
            httpServletResponse.setContentType("application/json");
            final ErrorResponse errorResponse = ErrorResponse.of(ErrorCode.UNAUTHORIZED);
            this.jWTTokenProvider.signOut(httpServletRequest, httpServletResponse);
            httpServletResponse.getWriter().write(objectMapper.writeValueAsString(errorResponse));

        }catch (IOException e){
            e.printStackTrace();
        }
    }

}