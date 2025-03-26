package com.example.hello.spring;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import javax.sql.DataSource;

@Configuration
@EnableJdbcHttpSession
public class HttpSessionConfig {

    public HttpSessionConfig
	(@Qualifier("sessionDataSource") DataSource dataSource) {
    }
}
