package com.av;

import com.av.app.security.RsaKeyConfigProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = {RsaKeyConfigProperties.class})
public class MovieReservationSystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(MovieReservationSystemApplication.class, args);
    }

}
