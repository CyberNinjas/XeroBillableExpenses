/*
 * Copyright (C) 2015 Cyber Ninjas Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.cyberninjas.xerobillableexpenses.util;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 * @author Doug Logan
 */
public class Settings {
    private Preferences prefs = null;
    private byte[] iv = null;
    private SecretKey secret = null;
    Cipher cipher = null;
    
    public Settings(){
        try {
            String parentClass = new Exception().getStackTrace()[1].getClassName();
            this.prefs = Preferences.userNodeForPackage(Class.forName(parentClass));
            Random r = new SecureRandom();
            
            //Set IV
            this.iv = prefs.getByteArray("DRUGS", null);
            
            //Pick Random PWD
            byte[] b = new byte[128];
            r.nextBytes(b);
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(b);
            String sHash = new String(Base64.encodeBase64(sha.digest()));

            String password = prefs.get("LAYOUT", sHash);
            if(password.equals(sHash)) prefs.put("LAYOUT", sHash);

            //Keep 'em Guessing
            r.nextBytes(b);
            sha.update(b);
            prefs.put("PASSWORD", new String(Base64.encodeBase64(sha.digest())));
            
            //Set Random Salt
            byte[] tSalt = new byte[8];
            r.nextBytes(tSalt);
            byte[] salt = prefs.getByteArray("HIMALAYAN", tSalt);
            if(Arrays.equals(salt, tSalt)) prefs.putByteArray("HIMALAYAN", salt);

            /* Derive the key, given password and salt. */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(spec);
            this.secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public void setSecretPref(String name, String value){
        prefs.put(name, this.encryptText(value));
    }
    public String getSecretPref(String name){
        String encVal = prefs.get(name, "");
        
        return encVal.isEmpty() ? "" : this.decryptText(encVal);
    }
    public void setPref(String name, String value){
        prefs.put(name, value);
    }
    public String getPref(String name){
        return prefs.get(name, "");
    }
    
    private String encryptText(String plainText){
        try {
            cipher.init(Cipher.ENCRYPT_MODE, this.secret);
            AlgorithmParameters params = cipher.getParameters();
            if(this.iv == null){
                this.iv = params.getParameterSpec(IvParameterSpec.class).getIV();
                prefs.putByteArray("DRUGS", this.iv);
            }
            byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));
            String ret = new String(Base64.encodeBase64(ciphertext));
            return ret;
        } catch (InvalidParameterSpecException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
   }
   
   private String decryptText(String cipherText){
        try {
            this.iv = prefs.getByteArray("DRUGS", null);
            byte[] cText = Base64.decodeBase64(cipherText); 
            /* Decrypt the message, given derived key and initialization vector. */
            cipher.init(Cipher.DECRYPT_MODE, this.secret, new IvParameterSpec(this.iv));
            String ret = new String(cipher.doFinal(cText), "UTF-8");
            return ret;
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
   }
   
   public String test(){
       return this.decryptText(this.encryptText("COOKIE"));
       /*
        try {
            
            String plainText = "TEST";
            System.out.println(plainText);
            
            cipher.init(Cipher.ENCRYPT_MODE, this.secret);
            AlgorithmParameters params = cipher.getParameters();
            
            byte[] iv1 = params.getParameterSpec(IvParameterSpec.class).getIV();
            prefs.putByteArray("DRUGS", iv1);
            byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));
            String encText = new String(ciphertext);
            
            System.out.println("ENC:".concat(encText));
            //System.out.println(this.decryptText(encText));
            
            byte[] iv2 = prefs.getByteArray("DRUGS", null);
            byte[] cText = Base64.decodeBase64(encText); 
            Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher2.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv2));
            System.out.println(new String(cipher2.doFinal(cText), "UTF-8"));
            
            return "";
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidParameterSpecException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        }   
        return "";//*/
   }
}
