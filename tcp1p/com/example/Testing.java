package com.example;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Testing implements Serializable {
    // SerialVersionUID harus sama jika ada (di kode asli tidak ada, jadi default)
    private String name;
    private int price;
    private String groovyScript; // Ini payload kita

    public Testing(String name, int price) {
        this.name = name;
        this.price = price;
        this.groovyScript = null;
    }
}
