package com.incrage.ao.users.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.session
    .jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.beans.factory.annotation.Qualifier;
import javax.sql.DataSource;

@Configuration
@EnableJdbcHttpSession
public class SessionConfig {
    //
    //public SessionConfig
    //    (@Qualifier("sessionDataSource") DataSource dataSource) {
    //}
}
