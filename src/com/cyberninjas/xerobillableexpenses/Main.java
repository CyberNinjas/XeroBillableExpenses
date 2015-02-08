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

import com.cyberninjas.xerobillableexpenses.util.RSAx509Cert;
import com.cyberninjas.xerobillableexpenses.util.Settings;
import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

/**
 *
 * @author Doug Logan
 */
public class Main extends javax.swing.JFrame {
    private RSAx509Cert certGen = new RSAx509Cert();
    private Settings settings = new Settings();
    /**
     * Creates new form Main
     */
    public Main() {
        initComponents();
        this.jTextConsumerKey.setText(settings.getSecretPref("CONSUMER_KEY"));
        this.jTextConsumerSecret.setText(settings.getSecretPref("CONSUMER_SECRET"));
        this.jTextAreaPublicKey.setText(settings.getPref("PUBLIC_KEY"));
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanelInvoicing = new javax.swing.JPanel();
        jPanelSettings = new javax.swing.JPanel();
        jLabelConsumerKey = new javax.swing.JLabel();
        jLabelConsumerSecret = new javax.swing.JLabel();
        jLabelPublicKey = new javax.swing.JLabel();
        jScrollPanePublicKey = new javax.swing.JScrollPane();
        jTextAreaPublicKey = new javax.swing.JTextArea();
        jTextConsumerSecret = new javax.swing.JTextField();
        jTextConsumerKey = new javax.swing.JTextField();
        jButtonApply = new javax.swing.JButton();
        jButtonChangeKey = new javax.swing.JButton();
        jLabelAuthor1 = new javax.swing.JLabel();
        jButtonXeroAppURL = new javax.swing.JButton();
        jPanelAbout = new javax.swing.JPanel();
        jLabelAuthorTitle = new javax.swing.JLabel();
        jLabelCompanyTitle = new javax.swing.JLabel();
        jLabelWebsiteTitle = new javax.swing.JLabel();
        jLabelVersionTitle = new javax.swing.JLabel();
        jLabelAuthor = new javax.swing.JLabel();
        jLabelCompany = new javax.swing.JLabel();
        jLabelVersion = new javax.swing.JLabel();
        jButtonCyberNinjasURL = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        javax.swing.GroupLayout jPanelInvoicingLayout = new javax.swing.GroupLayout(jPanelInvoicing);
        jPanelInvoicing.setLayout(jPanelInvoicingLayout);
        jPanelInvoicingLayout.setHorizontalGroup(
            jPanelInvoicingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 591, Short.MAX_VALUE)
        );
        jPanelInvoicingLayout.setVerticalGroup(
            jPanelInvoicingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 410, Short.MAX_VALUE)
        );

        jTabbedPane1.addTab("Invoicing", jPanelInvoicing);

        jLabelConsumerKey.setFont(jLabelConsumerKey.getFont().deriveFont(jLabelConsumerKey.getFont().getStyle() | java.awt.Font.BOLD, jLabelConsumerKey.getFont().getSize()+1));
        jLabelConsumerKey.setText("Consumer Key:");

        jLabelConsumerSecret.setFont(jLabelConsumerSecret.getFont().deriveFont(jLabelConsumerSecret.getFont().getStyle() | java.awt.Font.BOLD, jLabelConsumerSecret.getFont().getSize()+1));
        jLabelConsumerSecret.setText("Consumer Secret:");

        jLabelPublicKey.setFont(jLabelPublicKey.getFont().deriveFont(jLabelPublicKey.getFont().getStyle() | java.awt.Font.BOLD, jLabelPublicKey.getFont().getSize()+1));
        jLabelPublicKey.setText("Public Key:");

        jTextAreaPublicKey.setColumns(20);
        jTextAreaPublicKey.setRows(5);
        jScrollPanePublicKey.setViewportView(jTextAreaPublicKey);

        jTextConsumerSecret.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextConsumerSecretActionPerformed(evt);
            }
        });

        jButtonApply.setText("Apply");
        jButtonApply.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonApplyActionPerformed(evt);
            }
        });

        jButtonChangeKey.setText("Change Key");
        jButtonChangeKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonChangeKeyActionPerformed(evt);
            }
        });

        jLabelAuthor1.setFont(jLabelAuthor1.getFont().deriveFont(jLabelAuthor1.getFont().getStyle() & ~java.awt.Font.BOLD, jLabelAuthor1.getFont().getSize()+1));
        jLabelAuthor1.setText("Consumer Keys and Consumer Secrets can be obtain from Xero after you create a private application at:");

        jButtonXeroAppURL.setBackground(jPanelAbout.getBackground());
        jButtonXeroAppURL.setForeground(new java.awt.Color(51, 0, 255));
        jButtonXeroAppURL.setText("<html><u>https://api.xero.com/Application</u></html>");
        jButtonXeroAppURL.setToolTipText("Goto https://www.CyberNinjas.com");
        jButtonXeroAppURL.setAlignmentY(0.0F);
        jButtonXeroAppURL.setBorder(null);
        jButtonXeroAppURL.setBorderPainted(false);
        jButtonXeroAppURL.setContentAreaFilled(false);
        jButtonXeroAppURL.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        jButtonXeroAppURL.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jButtonXeroAppURL.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        jButtonXeroAppURL.setIconTextGap(0);
        jButtonXeroAppURL.setMargin(new java.awt.Insets(0, 0, 0, 0));
        jButtonXeroAppURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonXeroAppURLActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanelSettingsLayout = new javax.swing.GroupLayout(jPanelSettings);
        jPanelSettings.setLayout(jPanelSettingsLayout);
        jPanelSettingsLayout.setHorizontalGroup(
            jPanelSettingsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelSettingsLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanelSettingsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPanePublicKey)
                    .addGroup(jPanelSettingsLayout.createSequentialGroup()
                        .addComponent(jLabelConsumerKey)
                        .addGap(21, 21, 21)
                        .addComponent(jTextConsumerKey))
                    .addGroup(jPanelSettingsLayout.createSequentialGroup()
                        .addComponent(jLabelConsumerSecret)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jTextConsumerSecret))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelSettingsLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(jButtonChangeKey)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jButtonApply))
                    .addGroup(jPanelSettingsLayout.createSequentialGroup()
                        .addGroup(jPanelSettingsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabelPublicKey)
                            .addComponent(jLabelAuthor1)
                            .addComponent(jButtonXeroAppURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanelSettingsLayout.setVerticalGroup(
            jPanelSettingsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelSettingsLayout.createSequentialGroup()
                .addGap(4, 4, 4)
                .addComponent(jLabelAuthor1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonXeroAppURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelSettingsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabelConsumerKey)
                    .addComponent(jTextConsumerKey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelSettingsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabelConsumerSecret)
                    .addComponent(jTextConsumerSecret, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabelPublicKey)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPanePublicKey, javax.swing.GroupLayout.PREFERRED_SIZE, 258, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelSettingsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonApply)
                    .addComponent(jButtonChangeKey))
                .addGap(4, 4, 4))
        );

        jTabbedPane1.addTab("Settings", jPanelSettings);

        jLabelAuthorTitle.setFont(jLabelAuthorTitle.getFont().deriveFont(jLabelAuthorTitle.getFont().getStyle() | java.awt.Font.BOLD, jLabelAuthorTitle.getFont().getSize()+1));
        jLabelAuthorTitle.setText("Author:");

        jLabelCompanyTitle.setFont(jLabelCompanyTitle.getFont().deriveFont(jLabelCompanyTitle.getFont().getStyle() | java.awt.Font.BOLD, jLabelCompanyTitle.getFont().getSize()+1));
        jLabelCompanyTitle.setText("Company:");

        jLabelWebsiteTitle.setFont(jLabelWebsiteTitle.getFont().deriveFont(jLabelWebsiteTitle.getFont().getStyle() | java.awt.Font.BOLD, jLabelWebsiteTitle.getFont().getSize()+1));
        jLabelWebsiteTitle.setText("Website:");

        jLabelVersionTitle.setFont(jLabelVersionTitle.getFont().deriveFont(jLabelVersionTitle.getFont().getStyle() | java.awt.Font.BOLD, jLabelVersionTitle.getFont().getSize()+1));
        jLabelVersionTitle.setText("Version");

        jLabelAuthor.setFont(jLabelAuthor.getFont().deriveFont(jLabelAuthor.getFont().getStyle() & ~java.awt.Font.BOLD, jLabelAuthor.getFont().getSize()+1));
        jLabelAuthor.setText("Doug Logan");

        jLabelCompany.setFont(jLabelCompany.getFont().deriveFont(jLabelCompany.getFont().getStyle() & ~java.awt.Font.BOLD, jLabelCompany.getFont().getSize()+1));
        jLabelCompany.setText("Cyber Ninjas");

        jLabelVersion.setFont(jLabelVersion.getFont().deriveFont(jLabelVersion.getFont().getStyle() & ~java.awt.Font.BOLD, jLabelVersion.getFont().getSize()+1));
        jLabelVersion.setText("0.01 Beta");

        jButtonCyberNinjasURL.setBackground(jPanelAbout.getBackground());
        jButtonCyberNinjasURL.setForeground(new java.awt.Color(51, 0, 255));
        jButtonCyberNinjasURL.setText("<html><u>https://www.CyberNinjas.com</u></html>");
        jButtonCyberNinjasURL.setToolTipText("Goto https://www.CyberNinjas.com");
        jButtonCyberNinjasURL.setAlignmentY(0.0F);
        jButtonCyberNinjasURL.setBorder(null);
        jButtonCyberNinjasURL.setBorderPainted(false);
        jButtonCyberNinjasURL.setContentAreaFilled(false);
        jButtonCyberNinjasURL.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        jButtonCyberNinjasURL.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jButtonCyberNinjasURL.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        jButtonCyberNinjasURL.setIconTextGap(0);
        jButtonCyberNinjasURL.setMargin(new java.awt.Insets(0, 0, 0, 0));
        jButtonCyberNinjasURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonCyberNinjasURLActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanelAboutLayout = new javax.swing.GroupLayout(jPanelAbout);
        jPanelAbout.setLayout(jPanelAboutLayout);
        jPanelAboutLayout.setHorizontalGroup(
            jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelAboutLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabelCompanyTitle)
                    .addComponent(jLabelAuthorTitle)
                    .addComponent(jLabelWebsiteTitle)
                    .addComponent(jLabelVersionTitle))
                .addGap(18, 18, 18)
                .addGroup(jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabelCompany)
                    .addComponent(jLabelAuthor)
                    .addGroup(jPanelAboutLayout.createSequentialGroup()
                        .addGap(2, 2, 2)
                        .addComponent(jLabelVersion))
                    .addComponent(jButtonCyberNinjasURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(355, Short.MAX_VALUE))
        );
        jPanelAboutLayout.setVerticalGroup(
            jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelAboutLayout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addGroup(jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabelAuthor)
                    .addComponent(jLabelAuthorTitle))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabelCompanyTitle)
                    .addComponent(jLabelCompany))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabelWebsiteTitle)
                    .addComponent(jButtonCyberNinjasURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabelVersionTitle)
                    .addComponent(jLabelVersion))
                .addContainerGap(300, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab("About", jPanelAbout);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jTabbedPane1)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jTabbedPane1)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButtonCyberNinjasURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonCyberNinjasURLActionPerformed
        try {
            String url = jButtonCyberNinjasURL.getText().replaceAll("\\<[^>]*>","");
            final URI uri = new URI(url);
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(uri);
            }
      } catch (IOException e) { 
          
      } catch (URISyntaxException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
 
    }//GEN-LAST:event_jButtonCyberNinjasURLActionPerformed

    private void jTextConsumerSecretActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextConsumerSecretActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextConsumerSecretActionPerformed

    private void jButtonChangeKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonChangeKeyActionPerformed
        this.certGen.generateKeys();
        this.jTextAreaPublicKey.setText(this.certGen.getPublicKey());
    }//GEN-LAST:event_jButtonChangeKeyActionPerformed

    private void jButtonApplyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonApplyActionPerformed
        String consumerKey = this.jTextConsumerKey.getText().trim();
        String consumerSecret = this.jTextConsumerSecret.getText().trim();
        String publicKey = this.jTextAreaPublicKey.getText().trim();
        if(consumerKey.length() != 30){
            this.showDialog("Consumer Key is not 30 characters.", "Invalid Consumer Key");
            return;
        } 
        if(consumerSecret.length() != 30){
            this.showDialog("Consumer Secret is not 30 characters.", "Invalid Consumer Secret");
            return;
        }
        if(publicKey.isEmpty()){
            this.showDialog("Public Key must be specified. Click \"Change Key\" to generate", "Invalid Public Key");
            return;
        }
        
        if(!certGen.getPrivateKey().isEmpty())
            this.settings.setSecretPref("PRIVATE_KEY", certGen.getPrivateKey());
        this.settings.setPref("PUBLIC_KEY", publicKey);
        settings.setSecretPref("CONSUMER_KEY", consumerKey);
        settings.setSecretPref("CONSUMER_SECRET", consumerSecret);
        this.showDialog("Do not forget to add the Pubic Key to the matching API App entry where you got the Consumer Key & Secret!", "Success!");  
    }//GEN-LAST:event_jButtonApplyActionPerformed

    private void jButtonXeroAppURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonXeroAppURLActionPerformed
      try {
            String url = this.jButtonXeroAppURL.getText().replaceAll("\\<[^>]*>","");
            final URI uri = new URI(url);
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(uri);
            }
      } catch (IOException e) { 

      } catch (URISyntaxException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
      }
    }//GEN-LAST:event_jButtonXeroAppURLActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Main().setVisible(true);
            }
        });
    }
    private void showDialog(String message, String title){
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButtonApply;
    private javax.swing.JButton jButtonChangeKey;
    private javax.swing.JButton jButtonCyberNinjasURL;
    private javax.swing.JButton jButtonXeroAppURL;
    private javax.swing.JLabel jLabelAuthor;
    private javax.swing.JLabel jLabelAuthor1;
    private javax.swing.JLabel jLabelAuthorTitle;
    private javax.swing.JLabel jLabelCompany;
    private javax.swing.JLabel jLabelCompanyTitle;
    private javax.swing.JLabel jLabelConsumerKey;
    private javax.swing.JLabel jLabelConsumerSecret;
    private javax.swing.JLabel jLabelPublicKey;
    private javax.swing.JLabel jLabelVersion;
    private javax.swing.JLabel jLabelVersionTitle;
    private javax.swing.JLabel jLabelWebsiteTitle;
    private javax.swing.JPanel jPanelAbout;
    private javax.swing.JPanel jPanelInvoicing;
    private javax.swing.JPanel jPanelSettings;
    private javax.swing.JScrollPane jScrollPanePublicKey;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTextArea jTextAreaPublicKey;
    private javax.swing.JTextField jTextConsumerKey;
    private javax.swing.JTextField jTextConsumerSecret;
    // End of variables declaration//GEN-END:variables
}
