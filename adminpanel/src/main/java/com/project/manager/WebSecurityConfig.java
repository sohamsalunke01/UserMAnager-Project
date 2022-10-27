package com.project.manager;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.project.manager.oauth.CustomOAuth2User;
import com.project.manager.oauth.CustomOAuth2UserService;
import com.project.manager.oauth.OAuthLoginSuccessHandler;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private DataSource dataSource;

	@Bean
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailsService();
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());

		return authProvider;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}
	
	@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/", "/login", "/oauth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .formLogin().permitAll()
            .and()
            .oauth2Login()
                .loginPage("/login")
                .userInfoEndpoint()
                    .userService(oauthUserService);
        http.oauth2Login()
        .loginPage("/login")
        .userInfoEndpoint()
            .userService(oauthUserService)
        .and()
        .successHandler(new AuthenticationSuccessHandler() {
     
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                    Authentication authentication) throws IOException, ServletException {
     
                CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
     
                oauthUserService.processOAuthPostLogin(oauthUser.getEmail());
     
                response.sendRedirect("/list");
            	}
            }
            );
        }
     
    @Autowired
    private CustomOAuth2UserService oauthUserService;
    
    @Autowired
    private OAuthLoginSuccessHandler oAuth2LoginSuccessHandler;

//@Override
//protected void configure(HttpSecurity http) throws Exception{
//    http.authorizeRequests()
//    .antMatchers("/users").authenticated()
//    .anyRequest().permitAll()
//    .and() 
//    .formLogin()
//        .usernameParameter("email")
//        .defaultSuccessUrl("/users")
//        .permitAll()
//    .and()
//    .logout().logoutSuccessUrl("/").permitAll();
//}

}