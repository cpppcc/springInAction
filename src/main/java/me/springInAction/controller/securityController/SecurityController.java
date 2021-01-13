package me.springInAction.controller.securityController;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
@Configuration
public class SecurityController extends WebSecurityConfigurerAdapter {

    private static final String DEFAULT_PASSWORD = new BCryptPasswordEncoder().encode("12345678");

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("Mostafa").password(DEFAULT_PASSWORD).roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
                .antMatchers("/static/**/*").permitAll()
                .antMatchers("/home").permitAll()
                .antMatchers("/**").authenticated().and()
                .formLogin().successHandler((request , response , authentication) ->{
                    request.getSession(false).setAttribute("currentUser" , authentication.getPrincipal());
                    response.sendRedirect("/product");
                }).loginPage("/login").permitAll()
                .and().logout().permitAll().and().exceptionHandling().accessDeniedPage("/403");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
