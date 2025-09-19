package com.algoritmo_des;

import java.nio.charset.StandardCharsets;

public class DES {

    // Tabela de Permutação Inicial (IP)
    private static final int[] IP = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30,
            22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

    // Tabela de Permutação Final (IP Inversa)
    private static final int[] FP = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54,
            22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

    // Tabela de Expansão (E) - expande a metade direita de 32 para 48 bits
    private static final int[] E = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

    // Tabela de Permutação da Função de Feistel (P)
    private static final int[] P = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27,
            3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

    // S-Boxes (Caixas de Substituição) - 8 tabelas 4x16
    private static final int[][][] S_BOX = { {
            { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
            { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
            { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
            { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
            { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
            { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } } };

    // --- Tabelas de Geração de Chave ---

    // Permuted Choice 1 (PC-1) - Seleciona 56 bits da chave de 64
    private static final int[] PC1 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4 };

    // Permuted Choice 2 (PC-2) - Seleciona 48 bits da chave de 56 para cada rodada
    private static final int[] PC2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20,
            13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

    // Tabela de Rotação de Chave - número de shifts à esquerda por rodada
    private static final int[] SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    
    private String hexToBinary(String hex) {
        hex = hex.replaceAll("\\s", ""); // remove espaços
        StringBuilder binary = new StringBuilder();
        for (char hexChar : hex.toCharArray()) {
            int i = Integer.parseInt(String.valueOf(hexChar), 16);
            binary.append(String.format("%4s", Integer.toBinaryString(i)).replace(' ', '0'));
        }
        return binary.toString();
    }

    private String binaryToHex(String binary) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 4) {
            String fourBits = binary.substring(i, i + 4);
            int decimal = Integer.parseInt(fourBits, 2);
            hex.append(Integer.toString(decimal, 16));
        }
        return hex.toString().toUpperCase();
    }
    
    public String encryptWithAsciiKey(String plainText, String asciiKey) {
        String keyHex = asciiToHex(asciiKey);
        return encrypt(plainText, keyHex);
    }
    
    public String decryptWithAsciiKey(String ciphertextHex, String asciiKey) {
        String keyHex = asciiToHex(asciiKey);
        return decrypt(ciphertextHex, keyHex);
    }
    
    private String asciiToHex(String ascii) {
        if (ascii.length() != 8) {
            throw new IllegalArgumentException("A chave ASCII deve ter exatamente 8 caracteres.");
        }
        byte[] bytes = ascii.getBytes(StandardCharsets.UTF_8);
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }
    
    // Aplica uma permutação a uma string binária de entrada a partir de uma tabela definida
    private String permute(String inputBin, int[] table) {
        StringBuilder outputBin = new StringBuilder();
        for (int i = 0; i < table.length; i++) {
            outputBin.append(inputBin.charAt(table[i] - 1));
        }
        return outputBin.toString();
    }
    
    //Realiza uma operação XOR entre duas strings binárias.

    private String xor(String a, String b) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            result.append(a.charAt(i) ^ b.charAt(i));
        }
        return result.toString();
    }

    // Realiza um shift circular à esquerda em uma string
    private String leftShift(String bits, int n) {
        return bits.substring(n) + bits.substring(0, n);
    }
    
    //Gera as 16 sub-chaves de 48 bits a partir da chave principal de 64 bits, retorna um array de 16 string com 48 bits em cada
    private String[] generateSubKeys(String keyHex) {
        String keyBin = hexToBinary(keyHex);
        String keyPC1 = permute(keyBin, PC1); // Aplica PC-1 -> 56 bits

        String C = keyPC1.substring(0, 28);
        String D = keyPC1.substring(28, 56);

        String[] subKeys = new String[16];
        for (int i = 0; i < 16; i++) {
            C = leftShift(C, SHIFTS[i]);
            D = leftShift(D, SHIFTS[i]);
            String combinedCD = C + D;
            subKeys[i] = permute(combinedCD, PC2); // Aplica PC-2 -> 48 bits
        }
        return subKeys;
    }

    //Executa a função de Feistel (função f) em uma metade de 32 bits, recebendo a metade direita do bloco (32 bits) e a subchave da rodada atual
    private String feistelFunction(String rightHalf, String subKey) {
        // 1. Expansão
        String expandedRight = permute(rightHalf, E); // 32 -> 48 bits

        // 2. XOR com a sub-chave
        String xored = xor(expandedRight, subKey);

        // 3. Substituição S-Box
        StringBuilder sboxOutput = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            String sixBits = xored.substring(i * 6, (i * 6) + 6);
            String rowBits = "" + sixBits.charAt(0) + sixBits.charAt(5);
            String colBits = sixBits.substring(1, 5);
            int row = Integer.parseInt(rowBits, 2);
            int col = Integer.parseInt(colBits, 2);
            int sboxVal = S_BOX[i][row][col];
            sboxOutput.append(String.format("%4s", Integer.toBinaryString(sboxVal)).replace(' ', '0'));
        }
        
        // 4. Permutação P
        return permute(sboxOutput.toString(), P);
    }

    // Processa um único bloco de 64 bits (criptografa ou descriptografa)
    private String processBlock(String blockHex, String[] subKeys, boolean isEncrypting) {
        String blockBin = hexToBinary(blockHex);

        // 1. Permutação Inicial (IP)
        String permutedBlock = permute(blockBin, IP);

        // 2. Separa em metades L e R
        String L = permutedBlock.substring(0, 32);
        String R = permutedBlock.substring(32, 64);

        // 3. 16 Rodadas da Rede de Feistel
        for (int i = 0; i < 16; i++) {
            String tempR = R;
            int keyIndex = isEncrypting ? i : 15 - i;
            String fResult = feistelFunction(R, subKeys[keyIndex]);
            R = xor(L, fResult);
            L = tempR;
        }

        // 4. Combina as metades (com a troca final desfeita) e aplica a Permutação Final
        String combinedFinal = R + L; // A troca final da última rodada é revertida aqui
        String finalBlockBin = permute(combinedFinal, FP);

        return binaryToHex(finalBlockBin);
    }
    
    // Criptografa uma mensagem de texto plano. A mensagem é preenchida, dividida em blocos e cada bloco é criptografado.
    public String encrypt(String plainText, String keyHex) {
        String[] subKeys = generateSubKeys(keyHex);
        byte[] textBytes = plainText.getBytes(StandardCharsets.UTF_8);

        int paddingLen = 8 - (textBytes.length % 8);
        byte[] paddedBytes = new byte[textBytes.length + paddingLen];
        System.arraycopy(textBytes, 0, paddedBytes, 0, textBytes.length);
        for (int i = textBytes.length; i < paddedBytes.length; i++) {
            paddedBytes[i] = (byte) paddingLen;
        }

        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < paddedBytes.length; i += 8) {
            StringBuilder blockHex = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                blockHex.append(String.format("%02X", paddedBytes[i + j]));
            }
            ciphertext.append(processBlock(blockHex.toString(), subKeys, true));
        }

        return ciphertext.toString();
    }
    
    // Descriptografa uma mensagem cifrada em hexadecimal.
    public String decrypt(String ciphertextHex, String keyHex) {
        String[] subKeys = generateSubKeys(keyHex);
        StringBuilder decryptedBytesStr = new StringBuilder();

        for (int i = 0; i < ciphertextHex.length(); i += 16) {
            String blockHex = ciphertextHex.substring(i, i + 16);
            String decryptedBlock = processBlock(blockHex, subKeys, false);
            decryptedBytesStr.append(decryptedBlock);
        }

        // Converte de Hex para bytes e remove o padding
        String hexResult = decryptedBytesStr.toString();
        byte[] resultBytes = new byte[hexResult.length() / 2];
        for (int i = 0; i < resultBytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(hexResult.substring(index, index + 2), 16);
            resultBytes[i] = (byte) j;
        }

        int paddingLen = resultBytes[resultBytes.length - 1];
        if (paddingLen < 1 || paddingLen > 8) {
            // Padding inválido, retorna os bytes como estão
            return new String(resultBytes, StandardCharsets.UTF_8);
        }
        
        byte[] unpaddedBytes = new byte[resultBytes.length - paddingLen];
        System.arraycopy(resultBytes, 0, unpaddedBytes, 0, unpaddedBytes.length);
        
        return new String(unpaddedBytes, StandardCharsets.UTF_8);
    }
}