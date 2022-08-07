package com.jwt.dto;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class User implements Serializable {

    private static final long serialVersionUID = 1L;
    private String uid;
    private String name;
    private String lastName;
    private String role;
    private String country;
}
