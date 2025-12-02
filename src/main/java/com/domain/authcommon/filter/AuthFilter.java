package com.domain.authcommon.filter;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String username = request.getHeader("X-Username");
            if (StringUtils.isEmpty(username)) {
                throw new UsernameNotFoundException("Username not found");
            }
            String defaultRole = request.getHeader("X-Role");

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username, null,
                    AuthorityUtils.commaSeparatedStringToAuthorityList(defaultRole)
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } catch (UsernameNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
