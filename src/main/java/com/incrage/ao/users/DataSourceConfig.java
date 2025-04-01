package com.incrage.ao.users;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import javax.sql.DataSource;

@Configuration
public class DataSourceConfig {

    @Bean("sessionDataSource")
    @ConfigurationProperties(prefix = "session-data-source")
    public DataSource sessionDataSource() {
        return DataSourceBuilder.create().build();
    }
}
