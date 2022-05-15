package com.fabiangabor.nye.itsecurity.des.service;

import static com.fabiangabor.nye.itsecurity.des.domain.Constants.*;

public class DESImplementation implements DES {
    private String[] roundKeyArray = new String[16];
    private int leftSpace;

    @Override
    public String encrypt(String plainText, String key) {
        StringBuilder encoded = new StringBuilder();

        buildRoundKeyArray(key);

        String plainTextBinary;

        String binaryKey = strToBin(plainText);
        binaryKey = binaryKey.replace(" ", "");
        String binaryText = binaryKey;

        // Use plainTextBinary to form a loop
        if (binaryKey.length() < 64) {
            throw new IllegalArgumentException("Plaintext must be 64 bits long");
        }
        int leftPadString = calculateLeftPadStringLenght(binaryKey.length());
        int rounds = calculateLoopRounds(binaryKey.length(), leftPadString);
        int start = 0;
        int end = 64;
        int leftPad = 64 - leftPadString;
        leftSpace = calculateLeftPadStringLenght(leftPad) != 0 ? leftPad / 8 : 0;

        for (int i = rounds; i > 0; i--) {
            end = calculateEnd(binaryKey, start, end);
            plainTextBinary = padText(binaryText, start, end);

            StringBuilder ipBinary = permute(IP, plainTextBinary);
            String leftIPBinary = ipBinary.substring(0, 32);
            String rightIPBinary = ipBinary.substring(32, 64);

            int counter = 1;
            for (String k : roundKeyArray) {
                String leftBlock = rightIPBinary;
                rightIPBinary = calculateRightIPBinary(leftIPBinary, rightIPBinary, k);

                counter++;
                if (counter > 16) {
                    // Reversely combine the two blocks to form a 64-bit block
                    String xoredExpandAndKey = rightIPBinary + leftBlock;

                    //Final Permutation FP: The Inverse of the Initial permutation IP
                    StringBuilder finalResult = permute(FP, xoredExpandAndKey);

                    encoded.append(finalResult);
                }
                leftIPBinary = leftBlock;
            }
            end += 64;
            start += 64;
        }

        return encoded.toString();
    }

    private int calculateEnd(String binaryKey, int start, int end) {
        end = binaryKey.length() - start < 64 ? binaryKey.length() : end;
        return end;
    }

    private int calculateLeftPadStringLenght(int plainTextLength) {
        return plainTextLength % 64;
    }

    private int calculateLoopRounds(int plainTextLength, int leftPadString) {
        return leftPadString != 0 ? plainTextLength / 64 + 1 : plainTextLength / 64;
    }

    @Override
    public String decrypt(String encodedBinaryText, String key) {
        StringBuilder decoded = new StringBuilder();

        buildRoundKeyArray(key);

        int leftPadString = calculateLeftPadStringLenght(encodedBinaryText.length());
        int rounds = calculateLoopRounds(encodedBinaryText.length(), leftPadString);
        int start = 0;
        int end = 64;

        for (int i = rounds; i > 0; i--) {
            end = calculateEnd(encodedBinaryText, start, end);
            String cipherTextBinary = encodedBinaryText.substring(start, end);

            StringBuilder ipBinary = permute(IP, cipherTextBinary);
            String leftIPBinary = ipBinary.substring(0, 32);
            String rightIPBinary = ipBinary.substring(32, 64);

            int counter = 1;
            for (int p = 15; p >= 0; p--) {
                String k = roundKeyArray[p];

                String leftBlock = rightIPBinary;
                rightIPBinary = calculateRightIPBinary(leftIPBinary, rightIPBinary, k);

                counter++;
                if (counter > 16) {
                    String xoredExpandAndKey = rightIPBinary + leftBlock;
                    StringBuilder finalResult = permute(FP, xoredExpandAndKey);

                    decoded.append(i == 1 && leftSpace != 0 ?
                            intToStr(finalResult.toString(), 8).substring(leftSpace) : intToStr(finalResult.toString(), 8));
                }
                leftIPBinary = leftBlock;
            }

            end += 64;
            start += 64;
        }

        return decoded.toString().replaceAll("\\x00","");
    }

    private void buildRoundKeyArray(String key) {
        String binaryKey = strToBin(key).replace(" ", "");
        StringBuilder permutedKey = permute(PC1, binaryKey);

        /* Next, split this key into left and right halves, LK and RK, where each half has 28 bits. */
        /* Now, perform 16 left circular shifts from the original LK and RK */
        String lKey = permutedKey.substring(0, 28);
        String rKey = permutedKey.substring(28, 56);

        String[] keys = buildKeys(lKey, rKey);

        /* Then build the 16 48-bit sub keys using the PC-2 Permutation table */
        this.roundKeyArray = calculateRoundKeyArray(keys);
    }

    private String[] buildKeys(String lkey, String rKey) {
        String[] keys = new String[16];
        int index = 0;
        for (int binRotationVal : binaryRotation) {
            lkey = circularLeftShift(lkey, binRotationVal);
            rKey = circularLeftShift(rKey, binRotationVal);
            keys[index] = lkey + rKey;
            index++;
        }
        return keys;
    }

    private String[] calculateRoundKeyArray(String[] keys) {
        String[] rka = new String[16];
        StringBuilder roundKey = new StringBuilder();
        int index = 0;
        for (String key : keys) {
            for (int j : PC2) {
                roundKey.append(key.charAt(j - 1));
            }
            rka[index] = roundKey.toString();
            index++;
            roundKey = new StringBuilder();
        }
        return rka;
    }

    private String calculateRightIPBinary(String leftIPBinary, String rightIPBinary, String k) {
        //Right block is previous left block XOR F(previous left block, round key)
        //To calculate Right block we first expand 32 bit previous right block to 48 bits since the key is 48 bits
        StringBuilder expand = permute(EP, rightIPBinary);

        String xoredExpandAndKey = getXORedValue(k, expand);

        //"S boxes": 8 groups of six bits return as 4 bits in order for the Left block to regain its original 32 bits size
        String binaryTarget = calculateBinaryTarget(xoredExpandAndKey);

        //Lastly,to get f, permute the output of the S-box(binaryTarget) using table P to obtain the final value
        StringBuilder function = permute(P, binaryTarget);

        //Finally, Previous Left block XOR function value
        xoredExpandAndKey = getXORedValue(leftIPBinary, function);
        rightIPBinary = xoredExpandAndKey;
        return rightIPBinary;
    }

    private String padText(String binaryText, int start, int end) {
        StringBuilder plainTextBinary;
        plainTextBinary = new StringBuilder(binaryText.substring(start, end));
        while (plainTextBinary.length() != 64) {
            plainTextBinary.insert(0, "0");
        }
        return plainTextBinary.toString();
    }

    private String getXORedValue(String k, StringBuilder expand) {
        //XOR 'expand' and the key since they are now both 48 bits long
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < k.length(); i++) {
            sb.append((k.charAt(i) ^ expand.charAt(i)));
        }
        return sb.toString();
    }

    private StringBuilder permute(int[] p, String binaryTarget) {
        StringBuilder function = new StringBuilder();
        for (int d : p) {
            function.append(binaryTarget.charAt(d - 1));
        }
        return function;
    }

    private String calculateBinaryTarget(String result) {
        String rb1 = result.substring(0, 6);
        String row1 = rb1.charAt(0) + rb1.substring(5, 6);
        String col1 = rb1.substring(1, 5);
        int target = S1[Integer.parseInt(row1, 2)][Integer.parseInt(col1, 2)];
        String binaryTarget = String.format("%4s", Integer.toBinaryString(target)).replace(' ', '0');

        String rb2 = result.substring(6, 12);
        binaryTarget = buildBinaryTarget(binaryTarget, rb2, S2);

        String rb3 = result.substring(12, 18);
        binaryTarget = buildBinaryTarget(binaryTarget, rb3, S3);

        String rb4 = result.substring(18, 24);
        binaryTarget = buildBinaryTarget(binaryTarget, rb4, S4);

        String rb5 = result.substring(24, 30);
        binaryTarget = buildBinaryTarget(binaryTarget, rb5, S5);

        String rb6 = result.substring(30, 36);
        binaryTarget = buildBinaryTarget(binaryTarget, rb6, S6);

        String rb7 = result.substring(36, 42);
        binaryTarget = buildBinaryTarget(binaryTarget, rb7, S7);

        String rb8 = result.substring(42, 48);
        binaryTarget = buildBinaryTarget(binaryTarget, rb8, S8);

        return binaryTarget;
    }

    private String buildBinaryTarget(String binaryTarget, String rb, int[][] S) {
        String row;
        String col;
        int target;
        row = rb.charAt(0) + rb.substring(5, 6);
        col = rb.substring(1, 5);
        target = S[Integer.parseInt(row, 2)][Integer.parseInt(col, 2)];
        binaryTarget += String.format("%4s", Integer.toBinaryString(target)).replace(' ', '0');
        return binaryTarget;
    }

    /* Convert string to binary string */
    public String strToBin(String str) {

        byte[] bytes = str.getBytes();
        StringBuilder binary = new StringBuilder();
        for (byte b : bytes) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }
            binary.append(' ');
        }
        return binary.toString();
    }

    /* Convert integer to String */
    public String intToStr(String stream, int size) {

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < stream.length(); i += size) {
            result.append(stream, i, Math.min(stream.length(), i + size)).append(" ");
        }
        String[] ss = result.toString().split(" ");
        StringBuilder sb = new StringBuilder();
        for (String s : ss) {
            sb.append((char) Integer.parseInt(s, 2));
        }
        return sb.toString();
    }

    /* Left shift function */
    String circularLeftShift(String s, int k) {

        StringBuilder result = new StringBuilder(s.substring(k));
        for (int i = 0; i < k; i++) {
            result.append(s.charAt(i));
        }
        return result.toString();
    }

}