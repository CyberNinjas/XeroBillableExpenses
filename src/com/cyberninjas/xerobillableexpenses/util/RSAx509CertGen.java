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

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class RSAx509CertGen {
    private static String certDN = "CN=CyberNinjas,DC=XeroBillableExpenses";
    private static Integer certYears = 3;
    private String publicKey = "";
    private String privateKey = "";
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void generateKeys(){
        try {
            this.generateSelfSignedX509Certificate(certDN, certYears * 365);
        } catch (Exception ex) {
            Logger.getLogger(RSAx509CertGen.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public void setPublicKey(String key){
        this.publicKey = key;
    }
    public String getPublicKey(){
        return this.publicKey;
    }
    
    public void setPrivateKey(String key){
        this.privateKey = key;
    }
    public String getPrivateKey(){
        return this.privateKey;
    }

/**
 * Generate a self signed X509 certificate with Bouncy Castle.
 */
   private void generateSelfSignedX509Certificate(String strDN, Integer daysValid) throws Exception {
        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date validityEndDate = new Date(System.currentTimeMillis() + daysValid * 24 * 60 * 60 * 1000);

        // GENERATE THE PUBLIC/PRIVATE RSAx509CertGen KEY PAIR
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
}
