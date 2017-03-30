/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.digidoc4j.utils.Helper;
import org.junit.BeforeClass;

public class DigiDoc4JTestHelper {

  protected X509Certificate selfSignedCert;
  protected KeyPair keyPair;

  @BeforeClass
  public static void initSecurity() {
    Helper.ensureSecurityInitialized();
  }

  @BeforeClass
  public static void setConfigurationToTest() {
    System.setProperty("digidoc4j.mode", "TEST");
  }

  protected void ensureKeyPairAndX509() {
    try {
      if (keyPair == null) {
        // generate a key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        keyPair = keyPairGenerator.generateKeyPair();
      }
      if (selfSignedCert == null) {
        // create a certificate builder
        X500Name issuer = new X500Name("CN=Qeo Self Signed Cert");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + Long.valueOf("788400000000"));
        X500Name subject = new X500Name("CN=Qeo Self Signed Cert");
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        // Generate the certificate
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, publicKeyInfo);

        // Set certificate extensions
        // (1) digitalSignature extension
        certBuilder.addExtension(X509Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment));

        // (2) extendedKeyUsage extension
        Vector<KeyPurposeId> ekUsages = new Vector<KeyPurposeId>();
        ekUsages.add(KeyPurposeId.id_kp_clientAuth);
        ekUsages.add(KeyPurposeId.id_kp_emailProtection);
        certBuilder.addExtension(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(ekUsages));

        // (3) cRLDistributionPoints extension
        GeneralName gn1 = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String("http://www.qeo.org/test.crl", true));
        GeneralNames gns1 = new GeneralNames(gn1);
        DistributionPointName dpn1 = new DistributionPointName(gns1);
        DistributionPoint distp1 = new DistributionPoint(dpn1, null, null);

        GeneralName gn2 = new GeneralName(GeneralName.directoryName, new DERIA5String("CN=CRL1, OU=CloudId, O=Qeo, C=US"));
        GeneralNames gns2 = new GeneralNames(gn2);
        DistributionPointName dpn2 = new DistributionPointName(gns2);
        DistributionPoint distp2 = new DistributionPoint(dpn2, null, null);

        DistributionPoint[] distpArray = {distp1, distp2};
        DERSequence seq = new DERSequence(distpArray);
        certBuilder.addExtension(X509Extension.cRLDistributionPoints, false, seq);

        // Self sign the certificate
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1WithRSAEncryption");
        ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(contentSigner);

        // Retrieve the certificate from holder
        InputStream is1 = new ByteArrayInputStream(holder.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        selfSignedCert = (X509Certificate) cf.generateCertificate(is1);
      }
    } catch (Exception ex) {
      throw new RuntimeException("Could not generate self signed cert or key pair. Look inner exception for reason.", ex);
    }
  }
}
