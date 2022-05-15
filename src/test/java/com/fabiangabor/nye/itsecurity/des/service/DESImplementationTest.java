package com.fabiangabor.nye.itsecurity.des.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DESImplementationTest {


    private DES underTest;

    private final String TEXT = "Hello World!";

    private final String KEY = "0123456789ABCDEF";
    private final String encryptedBin =
            "00100100110101100110010010011111010010110010100110101000111101001001110010111011111010100100101110001010000010111110000101111000";

    @BeforeEach
    void setUp() {
        underTest = new DESImplementation();
    }

    @Test
    void encrypt() {
        String RESULT = underTest.encrypt(TEXT, KEY);
        assertEquals(encryptedBin, RESULT);
    }

    @Test
    void decrypt() {
        String RESULT = underTest.decrypt(encryptedBin, KEY);
        assertEquals(TEXT, RESULT);
    }
}