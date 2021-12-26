package com.wagner.springsecurityjdbc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    DataSource dataSource; //este projeto utiliza h2 database. Mas pode mudar o database no application.properties

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
// ========================================================
//        cria usuários user e admin no database através do código
// ========================================================
//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .withDefaultSchema()
//                .withUser(
//                        User.withUsername("user")
//                                .password("pass")
//                                .roles("USER")
//
//                )
//                .withUser(
//                        User.withUsername("admin")
//                                .password("pass")
//                                .roles("ADMIN")
//                );
// ========================================================

        // usa o usuário e senha gravados no database para fazer autenticação
        // aqui está se utilizando o Security Database Schema (padrão do spring)
        // esse schema está disponível em https://docs.spring.io/spring-security/site/docs/4.2.x/reference/html/appendix-schema.html
        auth.jdbcAuthentication()
                .dataSource(dataSource);

// ========================================================
//        se não utilizar o default schema, então vc pode informar o schema através desse exemplo:
// ========================================================
//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .usersByUsernameQuery("select username, password, enabled"
//                        + "from users "
//                        + "where username = ?"
//                )
//                .authoritiesByUsernameQuery("select username, authority"
//                        + "from authorities "
//                        + "where username = ?"
//                );

// ========================================================



    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ADMIN tem acesso a /admin
        // USER & ADMIN possuem acesso a /user
        // qualquer pessoa tem acesso ao root "/"
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("ADMIN", "USER")
                .antMatchers("/").permitAll()
                .and().formLogin();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        //TODO This PasswordEncoder is not secure.
        // Instead use an adaptive one way function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or SCryptPasswordEncoder.
        // Even better use DelegatingPasswordEncoder which supports password upgrades. There are no plans to remove this support.
        // It is deprecated to indicate that this is a legacy implementation and using it is considered insecure.
        return NoOpPasswordEncoder.getInstance();
    }

}
