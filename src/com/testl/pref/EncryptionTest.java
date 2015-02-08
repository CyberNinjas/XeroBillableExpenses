package com.testl.pref;
 
import java.util.prefs.*;
import javax.crypto.*;
 
public class EncryptionTest
{
  static private final String algorithm = "DES";
 
  static public void main( String args[] ) throws Exception {
   KeyGenerator keyGen = KeyGenerator.getInstance("DES");
   keyGen.init(56); // for example
   SecretKey secretKey = keyGen.generateKey();
 
    Preferences root =
      EncryptedPreferences.userNodeForPackage(
        EncryptionTest.class, secretKey );
 
    root.put( "transparent", "encryption" );
 
    Preferences subnode = root.node( "subnode" );
    subnode.put( "also", "encrypted" );
 
    root.exportSubtree( System.out );
    System.out.println(root.get("also", "def"));
  }
}
