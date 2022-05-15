package com.fabiangabor.nye.itsecurity.des.service;

import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

@Service
public interface DES {
    String encrypt(String text, String key);

    String decrypt(String text, String key);

}
