package io.security.basicsecurity;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  UserDetailsService userDetailsService;


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
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
            response.sendRedirect("/");
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

  }
}
