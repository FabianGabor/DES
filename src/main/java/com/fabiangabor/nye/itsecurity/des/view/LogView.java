package com.fabiangabor.nye.itsecurity.des.view;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LogView implements View{

    private static final Logger LOG = LoggerFactory.getLogger(LogView.class);

    @Override
    public void print(String message) {
        LOG.info(message);
    }
}
