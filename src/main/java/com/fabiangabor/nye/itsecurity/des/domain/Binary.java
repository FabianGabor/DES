package com.fabiangabor.nye.itsecurity.des.domain;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Binary {
    String value;

    public StringBuilder permute(int[] permuteArray) {
        StringBuilder permuted = new StringBuilder();
        for (int d : permuteArray) {
            permuted.append(value.charAt(d - 1));
        }
        return permuted;
    }
}
