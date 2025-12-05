package com.example.passwordmanager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    private static final String DB_FILE = "passwords.db";
    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: init | add | get | list");
            return;
        }
        String cmd = args[0];
        switch (cmd) {
            case "init" -> init();
            case "add" -> add();
            case "get" -> get();
            case "list" -> list();
            default -> System.out.println("Unknown command: " + cmd);
        }
    }

    private static Connection connect() throws SQLException {
        String url = "jdbc:sqlite:" + DB_FILE;
        return DriverManager.getConnection(url);
    }

    private static void init() throws Exception {
        try (Connection c = connect()) {
            try (Statement s = c.createStatement()) {
                s.execute("CREATE TABLE IF NOT EXISTS metadata(k TEXT PRIMARY KEY, v BLOB)");
                s.execute("CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, name TEXT UNIQUE, username TEXT, nonce BLOB, cipher BLOB)");
            }
            // generate and store salt
            byte[] salt = new byte[16];
            RNG.nextBytes(salt);
            try (PreparedStatement ps = c.prepareStatement("INSERT OR REPLACE INTO metadata(k,v) VALUES('salt',?)")) {
                ps.setBytes(1, salt);
                ps.executeUpdate();
            }
            System.out.println("Initialized DB and stored salt.");
        }
    }

    private static void add() throws Exception {
        try (Connection c = connect()) {
            byte[] salt = readSalt(c);
            char[] pass = readMasterPassword("Enter master password: ");
            SecretKey key = deriveKey(pass, salt);

            Scanner sc = new Scanner(System.in);
            System.out.print("Entry name: ");
            String name = sc.nextLine().trim();
            System.out.print("Username: ");
            String user = sc.nextLine().trim();
            System.out.print("Password: ");
            String pw = sc.nextLine();

            byte[] nonce = new byte[12]; RNG.nextBytes(nonce);
            byte[] cipher = encrypt(key, nonce, pw.getBytes(StandardCharsets.UTF_8));

            try (PreparedStatement ps = c.prepareStatement("INSERT OR REPLACE INTO entries(name,username,nonce,cipher) VALUES(?,?,?,?)")) {
                ps.setString(1, name);
                ps.setString(2, user);
                ps.setBytes(3, nonce);
                ps.setBytes(4, cipher);
                ps.executeUpdate();
            }
            System.out.println("Saved entry '"+name+"'.");
        }
    }

    private static void get() throws Exception {
        try (Connection c = connect()) {
            byte[] salt = readSalt(c);
            char[] pass = readMasterPassword("Enter master password: ");
            SecretKey key = deriveKey(pass, salt);

            Scanner sc = new Scanner(System.in);
            System.out.print("Entry name: ");
            String name = sc.nextLine().trim();

            try (PreparedStatement ps = c.prepareStatement("SELECT username, nonce, cipher FROM entries WHERE name = ?")) {
                ps.setString(1, name);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) { System.out.println("Not found"); return; }
                    String user = rs.getString(1);
                    byte[] nonce = rs.getBytes(2);
                    byte[] cipher = rs.getBytes(3);
                    byte[] plain = decrypt(key, nonce, cipher);
                    System.out.println("Name: " + name);
                    System.out.println("User: " + user);
                    System.out.println("Password: " + new String(plain, StandardCharsets.UTF_8));
                }
            }
        }
    }

    private static void list() throws SQLException {
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement("SELECT name, username FROM entries"); ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                System.out.println(rs.getString(1) + "\t" + rs.getString(2));
            }
        }
    }

    private static byte[] readSalt(Connection c) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT v FROM metadata WHERE k='salt'")) {
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new SQLException("Salt not found; run 'init' first");
                return rs.getBytes(1);
            }
        }
    }

    private static char[] readMasterPassword(String prompt) {
        Console con = System.console();
        if (con != null) {
            return con.readPassword(prompt);
        } else {
            // fallback
            System.out.print(prompt);
            Scanner s = new Scanner(System.in);
            return s.nextLine().toCharArray();
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 200_000, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encrypt(SecretKey key, byte[] nonce, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        return c.doFinal(plain);
    }

    private static byte[] decrypt(SecretKey key, byte[] nonce, byte[] cipherText) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        c.init(Cipher.DECRYPT_MODE, key, spec);
        return c.doFinal(cipherText);
    }
}
