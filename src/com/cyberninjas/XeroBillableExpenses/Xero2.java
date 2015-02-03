package com.cyberninjas.XeroBillableExpenses;

import com.connectifier.xeroclient.XeroApiException;
import com.connectifier.xeroclient.XeroClient;
import com.connectifier.xeroclient.models.*;
import com.cyberninjas.util.RSAx509Cert;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Xero2 {

    public static void main(String[] args) throws Exception {
        Reader pemReader = null;
        String consumerKey = "ILTWAUMMOYNJX3CEFJEHLJ6GORU1CN";
        String consumerSecret = "HA3BSU7WHRWARQ8MZWRAMYQ3D8ZCE4";
        RSAx509Cert x509 = new RSAx509Cert();
        
        pemReader = new StringReader(x509.getPrivateKey());
        XeroClient client = new XeroClient(pemReader, consumerKey, consumerSecret);
        //List<Invoice> i = client.getInvoices();
        //String where = "JournalID=Guid(\"124a0295-d27a-4932-9ff8-0c6d7b86ef6e\")";
        String where = "JournalLines.JournalLine.TrackingCategories.TrackingCategoryID=Guid(\"43bb5948-a4dd-4029-93be-f9274e15f5e6\")";
        List<Journal> j = client.getJournals(null, 0, where, null);
        //List<BankTransaction> trans = client.getBankTransactions();
        
       
        String a = "DEF";
        try {
            client.getUser("~");
        } catch (XeroApiException e){
            if(e.getResponseCode() == 401){
                System.out.println("You must import this key");
                System.out.println(x509.getPublicKey());
            }  else {
                System.out.println("Everything is setup!");
            }
        }
    }
    
}
