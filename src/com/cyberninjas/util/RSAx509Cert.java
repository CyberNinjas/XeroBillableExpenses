/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.cyberninjas.util;

import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Date;
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
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.apache.commons.codec.binary.Base64;

public class RSAx509Cert {
    private static String certDN = "CN=CyberNinjas,DC=XeroBillableExpenses";
    private static Integer certYears = 3;
    private String publicKey = "";
    private String privateKey = "";
    private byte[] iv = null;
    private SecretKey secret = null;
    private Preferences prefs = null;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public RSAx509Cert(){
        setPreferences();
    }
    
    private void setPreferences(){
        try {
            this.prefs = Preferences.userNodeForPackage(com.cyberninjas.XeroBillableExpenses.Xero2.class);
            Random r = new SecureRandom();
            
            this.iv = prefs.getByteArray("DRUGS", null);
            //Pick Random PWD
            byte[] b = new byte[128];
            r.nextBytes(b);
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(b);
            String sHash = new String(Base64.encodeBase64(sha.digest()));
            
            String password = prefs.get("LAYOUT", sHash);
            if(password.equals(sHash)) prefs.put("LAYOUT", sHash);
            
            //Set Random Salt
            byte[] tSalt = new byte[8];
            r.nextBytes(tSalt);
            byte[] salt = prefs.getByteArray("HIMALAYAN", tSalt);
            if(salt.equals(tSalt)) prefs.putByteArray("HIMALAYAN", salt);
            
            /* Derive the key, given password and salt. */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(spec);
            this.secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            
            String prKey = prefs.get("PRIVATE_KEY", "");
            String puKey = prefs.get("PUBLIC_KEY", "");
            if(prKey.isEmpty() || puKey.isEmpty()){
                this.generateSelfSignedX509Certificate(certDN, certYears * 365);
                prefs.put("PRIVATE_KEY", this.encryptText(this.privateKey));
                prefs.put("PUBLIC_KEY", this.publicKey);
            } else {
                this.privateKey = this.decryptText(prKey);
                this.publicKey = puKey;
                this.iv = prefs.getByteArray("DRUGS", new byte[8]);
            }   
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public String getPublicKey(){
        return this.publicKey;
    }

    public String getPrivateKey(){
        return this.privateKey;
    }

/**
 * Generate a self signed X509 certificate with Bouncy Castle.
 */
   public void generateSelfSignedX509Certificate(String strDN, Integer daysValid) throws Exception {
        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date validityEndDate = new Date(System.currentTimeMillis() + daysValid * 24 * 60 * 60 * 1000);

        // GENERATE THE PUBLIC/PRIVATE RSAx509Cert KEY PAIR
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // GENERATE THE X509 CERTIFICATE
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal dnName = new X500Principal(strDN);

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName); // use the same
        certGen.setNotBefore(validityBeginDate);
        certGen.setNotAfter(validityEndDate);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
        
        StringWriter textWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(textWriter);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        this.publicKey = textWriter.toString();
        
        textWriter = new StringWriter();
        pemWriter = new PEMWriter(textWriter);
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.flush();
        this.privateKey = textWriter.toString();
        
    }
   private String encryptText(String plainText){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.secret);
            AlgorithmParameters params = cipher.getParameters();
            if(this.iv == null){
                this.iv = params.getParameterSpec(IvParameterSpec.class).getIV();
                prefs.putByteArray("DRUGS", this.iv);
            }
            byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));
            return new String(Base64.encodeBase64(ciphertext));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidParameterSpecException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
   }
   
   private String decryptText(String cipherText){
        try {
            byte[] cText = Base64.decodeBase64(cipherText); 
            /* Decrypt the message, given derived key and initialization vector. */
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(this.iv));
            return new String(cipher.doFinal(cText), "UTF-8");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(RSAx509Cert.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
   }
}
