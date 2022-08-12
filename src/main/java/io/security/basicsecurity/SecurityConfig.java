package io.security.basicsecurity;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  UserDetailsService userDetailsService;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
    auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
    auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/user").hasRole("USER")
        .antMatchers("/admin/pay").hasRole("ADMIN")
        .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
        .anyRequest().authenticated();
    http
        .formLogin()
//        .loginPage("/loginPage")
        .defaultSuccessUrl("/")
        .failureUrl("/login")
        .usernameParameter("userId") // form 의 input name
        .passwordParameter("passwd") // form 의 input name
        .loginProcessingUrl("/login_proc") // form 의 action URL
        .successHandler(new AuthenticationSuccessHandler() {
          @Override
          public void onAuthenticationSuccess(HttpServletRequest request,
              HttpServletResponse response, Authentication authentication)
              throws IOException, ServletException {
            System.out.println("authentication : " + authentication.getName());

            // 로그인 성공 시 사용자가 이전에 가고자 했던 페이지로 리다이렉트
            RequestCache requestCache = new HttpSessionRequestCache();
            SavedRequest savedRequest =  requestCache.getRequest(request, response);
            String redirectUrl = savedRequest.getRedirectUrl();
            response.sendRedirect(redirectUrl);
          }
        })
        .failureHandler(new AuthenticationFailureHandler() {
          @Override
          public void onAuthenticationFailure(HttpServletRequest request,
              HttpServletResponse response, AuthenticationException exception)
              throws IOException, ServletException {
            System.out.println("exception : " + exception.getMessage());
            response.sendRedirect("/login");
          }
        })
        .permitAll();
    http
        .logout()
        .logoutUrl("/logout")
//        .logoutSuccessUrl("/login") // logoutSuccessHandler 을 사용하면 logoutSuccessUrl 은 무시된다
        .addLogoutHandler(new LogoutHandler() {
          @Override
          public void logout(HttpServletRequest request, HttpServletResponse response,
              Authentication authentication) {
            HttpSession session = request.getSession();
            session.invalidate();
          }
        })
        .logoutSuccessHandler(new LogoutSuccessHandler() {
          @Override
          public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
              Authentication authentication) throws IOException, ServletException {
            response.sendRedirect("/login");
          }
        })
        .deleteCookies("remember-me");
      http
          .rememberMe()
          .rememberMeParameter("remember-me") // default: remember-me, checkbox 등의 이름과 맞춰야함
          .tokenValiditySeconds(3600) // 쿠키의 만료시간 설정(초), default: 14일
          .alwaysRemember(false) // 사용자가 체크박스를 활성화하지 않아도 항상 실행, default: false
          .userDetailsService(userDetailsService);
      http
          .sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 세션 정책
          .sessionFixation().changeSessionId() // 세션 아이디 값을 변경함 (changeSessionId 가 기본값), 세션 고정 공격을 방지하기 위함
          .maximumSessions(1)
          .maxSessionsPreventsLogin(false); // default : false (이전 사용자의 세션을 만료), true : 이후 사용자의 로그인을 막음
      http
          .exceptionHandling()
//          .authenticationEntryPoint(new AuthenticationEntryPoint() {
//            @Override
//            public void commence(HttpServletRequest request, HttpServletResponse response,
//                AuthenticationException authException) throws IOException, ServletException {
//              response.sendRedirect("/login"); // 인증 실패 시 로그인 페이지로 이동
//            }
//          })
          .accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response,
                AccessDeniedException accessDeniedException) throws IOException, ServletException {
              response.sendRedirect("/denied"); // 인가 실패 시 인가실패 페이지로 이동
            }
          });

  }
}
