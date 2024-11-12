package main.java.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordManagement {

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private final static String HASH_ALGORITHM = "MD5";
    private final static int PW_DIFFICULTY = 9;

    /**
     * Minimum password length: 8 Characters
     * Maximum password length: 64 Characters
     * Suggested Password length: 20 or more Characters
     * Has to contain at least one lowercase letter
     * Has to contain at least one uppercase letter
     * Has to contain at least one number
     * Has to contain at least one special character
     * @param password The password set by the user
     * @return boolean true for success, false for failure
     */
    public boolean checkPasswordStrength(String password){

        int iPasswordScore = 0;

        if( password.length() < 8 || password.length() > 64 )
            return false;

        else if( password.length() >= 20 )
            iPasswordScore += 2;
        else
            iPasswordScore += 1;

        if( password.matches("(?=.*[0-9]).*") )
            iPasswordScore += 2;

        if( password.matches("(?=.*[a-z]).*") )
            iPasswordScore += 2;

        if( password.matches("(?=.*[A-Z]).*") )
            iPasswordScore += 2;

        if( password.matches("(?=.*[~!@#$%^&*()_-]).*") )
            iPasswordScore += 2;

        return iPasswordScore >= PW_DIFFICULTY;
    }


    /**
     * Hashes the input string using md5 hashing algorithm
     * @param data the string to be hashed
     * @return hexadecimal hash string
     * @throws NoSuchAlgorithmException, NoSuchProviderException
     */
    public String generateHash(String data) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        md.update(createSalt());
        byte[] hash = md.digest(data.getBytes());
        return bytesToStringHex(hash);
    }


    /**
     * Converts the byte hash string to a hexadecimal hash string
     * @param bytes A byte array
     * @return hexadecimal hash String
     */
    private static String bytesToStringHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++){
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    /**
     * Generates a salt to randomize the provided password
     * @param none
     * @return byte array of the randomly generated salt
     * @throws NoSuchAlgorithmException, NoSuchProviderException
     */
    private static byte[] createSalt() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom rn = SecureRandom.getInstance("SHA1PRNG","SUN");
        byte[] salt = new byte[16];
        rn.nextBytes(salt);
        return salt;
    }
}