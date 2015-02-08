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
package com.cyberninjas.xerobillableexpenses;

import com.connectifier.xeroclient.XeroApiException;
import com.connectifier.xeroclient.XeroClient;
import com.connectifier.xeroclient.models.*;
import com.cyberninjas.xerobillableexpenses.util.RSAx509CertGen;
import java.io.Reader;
import java.io.StringReader;
import java.util.List;

public class XeroTest {

    public static void main(String[] args) throws Exception {
        Reader pemReader = null;
        String consumerKey = "";
        String consumerSecret = "";
        RSAx509CertGen x509 = new RSAx509CertGen();
        
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
