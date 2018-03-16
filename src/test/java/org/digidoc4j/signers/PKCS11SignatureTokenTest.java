/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.signers;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.test.TestAssert;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.PrefilledPasswordCallback;

/**
 * PKCS#11 module path depends on your operating system and installed smart card or hardware token library.
 *
 * If you are using OpenSC (https://github.com/OpenSC/OpenSC/wiki), then
 * For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll
 * For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
 * For OSX, it could be /usr/local/lib/opensc-pkcs11.so
 *
 */
@Ignore("Requires a physical smart card for testing. Smart card issuer is TEST of ESTEID-SK 2015 and and CN is Igor Ž. Certificate serial 169229412855358073476555321630882129183. Document nr AS0013055")
public class PKCS11SignatureTokenTest extends AbstractTest {

  private static final byte[] dataToSign = new byte[]{60, 100, 115, 58, 83, 105, 103, 110, 101, 100, 73, 110, 102, 111, 32, 120, 109, 108, 110, 115, 58, 100, 115, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 50, 48, 48, 48, 47, 48, 57, 47, 120, 109, 108, 100, 115, 105, 103, 35, 34, 62, 60, 100, 115, 58, 67, 97, 110, 111, 110, 105, 99, 97, 108, 105, 122, 97, 116, 105, 111, 110, 77, 101, 116, 104, 111, 100, 32, 65, 108, 103, 111, 114, 105, 116, 104, 109, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 50, 48, 48, 49, 47, 49, 48, 47, 120, 109, 108, 45, 101, 120, 99, 45, 99, 49, 52, 110, 35, 34, 62, 60, 47, 100, 115, 58, 67, 97, 110, 111, 110, 105, 99, 97, 108, 105, 122, 97, 116, 105, 111, 110, 77, 101, 116, 104, 111, 100, 62, 60, 100, 115, 58, 83, 105, 103, 110, 97, 116, 117, 114, 101, 77, 101, 116, 104, 111, 100, 32, 65, 108, 103, 111, 114, 105, 116, 104, 109, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 50, 48, 48, 49, 47, 48, 52, 47, 120, 109, 108, 100, 115, 105, 103, 45, 109, 111, 114, 101, 35, 114, 115, 97, 45, 115, 104, 97, 50, 53, 54, 34, 62, 60, 47, 100, 115, 58, 83, 105, 103, 110, 97, 116, 117, 114, 101, 77, 101, 116, 104, 111, 100, 62, 60, 100, 115, 58, 82, 101, 102, 101, 114, 101, 110, 99, 101, 32, 73, 100, 61, 34, 114, 45, 105, 100, 45, 49, 34, 32, 84, 121, 112, 101, 61, 34, 34, 32, 85, 82, 73, 61, 34, 116, 101, 115, 116, 46, 116, 120, 116, 34, 62, 60, 100, 115, 58, 68, 105, 103, 101, 115, 116, 77, 101, 116, 104, 111, 100, 32, 65, 108, 103, 111, 114, 105, 116, 104, 109, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 50, 48, 48, 49, 47, 48, 52, 47, 120, 109, 108, 101, 110, 99, 35, 115, 104, 97, 50, 53, 54, 34, 62, 60, 47, 100, 115, 58, 68, 105, 103, 101, 115, 116, 77, 101, 116, 104, 111, 100, 62, 60, 100, 115, 58, 68, 105, 103, 101, 115, 116, 86, 97, 108, 117, 101, 62, 82, 113, 68, 113, 116, 113, 105, 51, 114, 84, 115, 87, 106, 48, 55, 114, 114, 87, 99, 53, 107, 65, 84, 65, 90, 73, 119, 55, 84, 49, 88, 72, 80, 47, 78, 80, 76, 67, 70, 48, 53, 82, 85, 61, 60, 47, 100, 115, 58, 68, 105, 103, 101, 115, 116, 86, 97, 108, 117, 101, 62, 60, 47, 100, 115, 58, 82, 101, 102, 101, 114, 101, 110, 99, 101, 62, 60, 100, 115, 58, 82, 101, 102, 101, 114, 101, 110, 99, 101, 32, 84, 121, 112, 101, 61, 34, 104, 116, 116, 112, 58, 47, 47, 117, 114, 105, 46, 101, 116, 115, 105, 46, 111, 114, 103, 47, 48, 49, 57, 48, 51, 35, 83, 105, 103, 110, 101, 100, 80, 114, 111, 112, 101, 114, 116, 105, 101, 115, 34, 32, 85, 82, 73, 61, 34, 35, 120, 97, 100, 101, 115, 45, 105, 100, 45, 100, 101, 97, 97, 53, 101, 52, 98, 101, 97, 97, 55, 102, 48, 97, 102, 49, 102, 100, 52, 99, 55, 101, 51, 49, 100, 100, 55, 50, 52, 57, 50, 34, 62, 60, 100, 115, 58, 84, 114, 97, 110, 115, 102, 111, 114, 109, 115, 62, 60, 100, 115, 58, 84, 114, 97, 110, 115, 102, 111, 114, 109, 32, 65, 108, 103, 111, 114, 105, 116, 104, 109, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 50, 48, 48, 49, 47, 49, 48, 47, 120, 109, 108, 45, 101, 120, 99, 45, 99, 49, 52, 110, 35, 34, 62, 60, 47, 100, 115, 58, 84, 114, 97, 110, 115, 102, 111, 114, 109, 62, 60, 47, 100, 115, 58, 84, 114, 97, 110, 115, 102, 111, 114, 109, 115, 62, 60, 100, 115, 58, 68, 105, 103, 101, 115, 116, 77, 101, 116, 104, 111, 100, 32, 65, 108, 103, 111, 114, 105, 116, 104, 109, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 50, 48, 48, 49, 47, 48, 52, 47, 120, 109, 108, 101, 110, 99, 35, 115, 104, 97, 50, 53, 54, 34, 62, 60, 47, 100, 115, 58, 68, 105, 103, 101, 115, 116, 77, 101, 116, 104, 111, 100, 62, 60, 100, 115, 58, 68, 105, 103, 101, 115, 116, 86, 97, 108, 117, 101, 62, 73, 114, 117, 116, 56, 49, 75, 108, 75, 115, 117, 97, 112, 69, 115, 57, 70, 85, 118, 52, 86, 43, 71, 72, 117, 76, 101, 118, 74, 53, 47, 66, 47, 83, 117, 52, 50, 48, 104, 98, 84, 48, 56, 61, 60, 47, 100, 115, 58, 68, 105, 103, 101, 115, 116, 86, 97, 108, 117, 101, 62, 60, 47, 100, 115, 58, 82, 101, 102, 101, 114, 101, 110, 99, 101, 62, 60, 47, 100, 115, 58, 83, 105, 103, 110, 101, 100, 73, 110, 102, 111, 62};
  private static final String expectedSignatureinHex = "49D438E821F1AD841D275DD890FBCB74748BE4F979BF81FBEE83CC4606F09E23189EAA6BBDF4E9D8F1CE0021EC9D97E35044D5B9D8B816EA59F06BD0F923CE9F351CFDC2A3A7DC4F0A77D08A0E7E158AD15FE0420D994B984731EF04C98CDE6CB0CA34001332EF157F27747797897531758B1B8E31BEF3D7A89B1ACF4D28E44B1734A51D31E325CF7E076D2DC29AAECF9303F3DFE3D137F21638219896CC978E3D3E26433DAB592FA773B2EFD461ABABAD4D8E70D62EBE7529AD672B3FB1A30A3658196326E61B6919B3FC2F466559ECE75A8E4E4EE751CDF1C3B55388B6DC1A35C219B52AD120481879800124A84A98BAAB92C31A7DF3B0E09B2C8D718C5C55";
  private static final String expectedSignatureinHexWithSha512 = "81128BA4FE29966B614416BFC54B8E6BF18B75B51A7AC8528EC3A1452872B3EA8914DF0E787CCFF5D3ABAA9D363CDD4891ED3B35C6FAFD3E42C1A6D6BA4769FC721B514B98FC1708A4ECB0AADAB9FF89A017D9C2156839E4E85E059E7B3FCBAAF225480093BE897B6E6FEB5F26638223AF5C4AD0B8DCCB96B2A000E517D8543EA4F2C1817FF4450F47D14D00C8333BDB40F7E408948DDBB1663AF364340F8FB44080ED9B731A2BDD28FA2C6FB55E993F33079B7C57FDDC3C6B345D1360D82F5242A857F27EA71DC3012EA1B069100824AF6729F1C878A29C6C81F83101B711B03707CA4D5F7A54952443F7F80CE5B5FCC88174249B303E50B48C5F30A952D865";
  private static final String PKCS_11_MODULE_PATH = "/usr/local/lib/opensc-pkcs11.so";
  private SignatureToken signatureToken;

  @Test
  public void signContainerWithSmartCard() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, DigestAlgorithm.SHA256, this.signatureToken);
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void signDDocContainerWithSmartCard() throws Exception {
    Container container = this.createNonEmptyContainerBy(Container.DocumentType.DDOC);
    this.createSignatureBy(container, DigestAlgorithm.SHA1, this.signatureToken);
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void fetchCertificateFromSmartCard() throws Exception {
    X509Certificate certificate = this.signatureToken.getCertificate();
    Assert.assertNotNull(certificate);
    Assert.assertThat(certificate.getSubjectDN().getName(), Matchers.containsString("CN"));
  }

  @Test
  public void signHashWithSmartCard() throws Exception {
    this.assertSignatureHash(this.signatureToken, DigestAlgorithm.SHA256, this.dataToSign, this.expectedSignatureinHex);
  }

  @Test
  public void signSha512HashWithSmartCard() throws Exception {
    this.assertSignatureHash(this.signatureToken, DigestAlgorithm.SHA512, this.dataToSign, this.expectedSignatureinHexWithSha512);
  }

  @Test
  public void selectPrivateKeyAndSignHash() throws Exception {
    PKCS11SignatureToken token = (PKCS11SignatureToken) this.signatureToken;
    List<DSSPrivateKeyEntry> privateKeyEntries = token.getPrivateKeyEntries();
    DSSPrivateKeyEntry keyEntry = privateKeyEntries.get(0);
    token.usePrivateKeyEntry(keyEntry);
    this.assertSignatureHash(token, DigestAlgorithm.SHA256, this.dataToSign, this.expectedSignatureinHex);
  }

  @Test
  public void selectCertificateWithPasswordCallback() throws Exception {
    PasswordInputCallback passwordCallback = new PrefilledPasswordCallback("22975".toCharArray());
    PKCS11SignatureToken signatureToken = new PKCS11SignatureToken(PKCS11SignatureTokenTest.PKCS_11_MODULE_PATH, passwordCallback, 2);
    List<DSSPrivateKeyEntry> privateKeyEntries = signatureToken.getPrivateKeyEntries();
    Assert.assertNotNull(privateKeyEntries);
    Assert.assertFalse(privateKeyEntries.isEmpty());
    this.assertSignatureHash(signatureToken, DigestAlgorithm.SHA256, this.dataToSign, this.expectedSignatureinHex);
  }

  @Test
  public void testSignContainerWithSmartCard() {
    Container container = this.createNonEmptyContainer();
    Signature signature = this.createSignatureBy(container, this.signatureToken);
    container.addSignature(signature);
    container.saveAsFile(this.getFileBy("bdoc"));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.signatureToken = new PKCS11SignatureToken(PKCS11SignatureTokenTest.PKCS_11_MODULE_PATH, "22975".toCharArray(), 2);
  }

  private void assertSignatureHash(SignatureToken signatureToken, DigestAlgorithm digestAlgorithm, byte[] dataToSign, String expectedSignatureinHex) {
    byte[] signatureValue = signatureToken.sign(digestAlgorithm, dataToSign);
    Assert.assertNotNull(signatureValue);
    String signatureInHex = DatatypeConverter.printHexBinary(signatureValue);
    Assert.assertEquals(expectedSignatureinHex, signatureInHex);
  }

}
