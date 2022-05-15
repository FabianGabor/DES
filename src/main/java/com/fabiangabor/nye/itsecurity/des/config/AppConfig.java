package com.fabiangabor.nye.itsecurity.des.config;

import com.fabiangabor.nye.itsecurity.des.service.DES;
import com.fabiangabor.nye.itsecurity.des.service.DESImplementation;
import com.fabiangabor.nye.itsecurity.des.view.LogView;
import com.fabiangabor.nye.itsecurity.des.view.View;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public DES des() {
        return new DESImplementation();
    }

    @Bean
    public View view() {
        return new LogView();
    }

}
