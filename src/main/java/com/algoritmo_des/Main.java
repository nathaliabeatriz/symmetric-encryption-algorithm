package com.algoritmo_des;

import java.util.Scanner;
        
public class Main {
    public static void main(String[] args) {
        DES des = new DES();
        Scanner scan = new Scanner(System.in);
        while(true){
            System.out.println("O que você deseja fazer?");
            System.out.println("1 - Criptografar uma mensagem");
            System.out.println("2 - Descriptografar uma mensagem");
            System.out.println("3 - Fechar programa");
            int op = scan.nextInt(); 
            scan.nextLine();
            switch(op){
                case 1 -> {
                    System.out.println("Digite a mensagem:");
                    String msg = scan.nextLine();
                    String key;
                    while(true){
                        System.out.println("Digite a chave para criptografar (Necessário 8 caracteres):");
                        key = scan.nextLine();
                        if(key.length() != 8){
                            System.out.println("Necessário 8 caracteres!");
                        }
                        else{
                            break;
                        }
                    }
                    String encryptedText = des.encryptWithAsciiKey(msg, key);
                    System.out.println("Texto criptografado (Hex): " + encryptedText);
                }
                
                case 2 -> {
                    System.out.println("Digite a mensagem criptografada:");
                    String msg = scan.nextLine();
                    String key;
                    while(true){
                        System.out.println("Digite a chave para descriptografar (Necessário 8 caracteres):");
                        key = scan.nextLine();
                        if(key.length() != 8){
                            System.out.println("Necessário 8 caracteres!");
                        }
                        else{
                            break;
                        }
                    }
                    String encryptedText = des.decryptWithAsciiKey(msg, key);
                    System.out.println("Texto descriptografado: " + encryptedText);
                }
                case 3 -> {
                    return;
                }
                    
            }
        }
    }
}