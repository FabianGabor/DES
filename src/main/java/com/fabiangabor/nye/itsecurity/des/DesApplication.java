package com.fabiangabor.nye.itsecurity.des;

import com.fabiangabor.nye.itsecurity.des.service.DES;
import com.fabiangabor.nye.itsecurity.des.view.View;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.math.BigInteger;

@SpringBootApplication
public class DesApplication {

    public static final String HR = "-----------------------------------------------------";
    private final DES cipher;
    private final View view;

    @Autowired
    public DesApplication(DES cipher, View view) {
        this.cipher = cipher;
        this.view = view;
    }

    public static void main(String[] args) {
        SpringApplication.run(DesApplication.class, args);
    }

    @Bean
    public CommandLineRunner run() {
        return args -> {
            String text = "Hello World!"; // needs to be 16 leghts (2 bytes per char)
            String key  = "0123456789ABCDEF"; // needs to be 16 leghts

            view.print(HR);
            view.print("Plain Text: " + text);

            view.print(HR);
            text = cipher.encrypt(text, key);

            String hexString = new BigInteger(text, 2).toString(16);
            view.print("HEX Text: " + hexString);

            view.print("Binary Text: " + text.toUpperCase());
            view.print("Key: " + key.toUpperCase() + " (" + key.length() + ")");

            view.print(HR);
            text = cipher.decrypt(text, key);
            view.print("Plain Text: " + text);
        };
    }

}
