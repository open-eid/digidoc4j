/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.test.MockConfigManagerInitializer;
import org.digidoc4j.test.MockDDocFacade;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;

import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

public class DDocFacadeTest extends AbstractTest {

  @Test(expected = DigiDoc4JException.class)
  public void testSaveThrowsException() throws Exception {
    new DDocFacade().save("/not/existing/path/testSaveThrowsException.ddoc");
  }

  @Test
  public void testGetDataFileSize() {
    DDocFacade container = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    org.digidoc4j.DataFile dataFile = container.getDataFile(0);
    Assert.assertEquals(16, dataFile.getFileSize());
  }

  @Test
  public void testSetDigestAlgorithmSHA1() throws Exception {
    DDocFacade container = new DDocFacade();
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
    container.setSignatureParameters(signatureParameters);
  }

  @Test(expected = NotSupportedException.class)
  public void testSetDigestAlgorithmOtherThenSHA1() throws Exception {
    DDocFacade container = new DDocFacade();
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA224);
    container.setSignatureParameters(signatureParameters);
  }

  @Test
  public void testCanAddTwoDataFilesWithSameName() throws Exception {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    String file = this.getFileBy("ddoc");
    facade.save(file);
    Container container = this.openContainerBy(Paths.get(file));
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();
    Assert.assertEquals(2, dataFiles.size());
    Assert.assertEquals("test.txt", dataFiles.get(0).getName());
    Assert.assertEquals("test.txt", dataFiles.get(1).getName());
  }

  @Test
  public void testGetFileId() {
    DDocFacade container = new DDocFacade();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();
    Assert.assertEquals("D0", dataFiles.get(0).getId());
    Assert.assertEquals("D1", dataFiles.get(1).getId());
    Assert.assertEquals("test.txt", dataFiles.get(0).getName());
    Assert.assertEquals("test.txt", dataFiles.get(1).getName());
  }

  @Test
  public void testAddEmptyFile() throws Exception {
    DDocFacade facade = new DDocFacade();
    String file = this.getFileBy("txt", true);
    facade.addDataFile(file, "text/plain");
    file = this.getFileBy("ddoc");
    facade.save(file);
    Container container = this.openContainerBy(Paths.get(file));
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();
    Assert.assertEquals(1, dataFiles.size());
    Assert.assertEquals(0, dataFiles.get(0).getFileSize());
  }

  @Test
  public void getDataFileByIndex() {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/plain");
    Assert.assertEquals("D0", facade.getDataFile(0).getId());
    Assert.assertEquals("D1", facade.getDataFile(1).getId());
    Assert.assertEquals("test.txt", facade.getDataFile(0).getName());
    Assert.assertEquals("test.xml", facade.getDataFile(1).getName());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddFileFromStreamToDDocThrowsException() throws DigiDocException, IOException {
    SignedDoc ddoc = Mockito.mock(SignedDoc.class);
    Mockito.when(ddoc.getNewDataFileId()).thenReturn("A");
    Mockito.when(ddoc.getFormat()).thenReturn("SignedDoc.FORMAT_DDOC");
    Mockito.doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(Matchers.any(ee.sk.digidoc.DataFile.class));
    try (ByteArrayInputStream stream = new ByteArrayInputStream(new byte[]{0x42})) {
      new DDocFacade(ddoc).addDataFile(stream, "testFromStream.txt", "text/plain");
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileThrowsException() throws Exception {
    SignedDoc ddoc = Mockito.mock(SignedDoc.class);
    Mockito.doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(Matchers.any(File.class), Matchers.any(String.class), Matchers.any(String.class));
    new DDocFacade(ddoc).addDataFile("src/test/resources/testFiles/helper-files/test.txt", "");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testGetDataFileThrowsException() throws Exception {
    SignedDoc ddoc = Mockito.spy(new SignedDoc("DIGIDOC-XML", "1.3"));
    ee.sk.digidoc.DataFile dataFile = Mockito.mock(ee.sk.digidoc.DataFile.class);
    Mockito.doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).when(dataFile).getBody();
    ArrayList<ee.sk.digidoc.DataFile> mockedDataFiles = new ArrayList<>();
    mockedDataFiles.add(dataFile);
    Mockito.doReturn(mockedDataFiles).when(ddoc).getDataFiles();
    DDocFacade facade = new DDocFacade(ddoc);
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.getDataFiles();
  }

  @Test
  public void testGetDataFilesWhenNoDataFileExists() {
    Assert.assertTrue(new DDocFacade().getDataFiles().isEmpty());
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileWhenNotFound() throws Exception {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.removeDataFile("NotThere.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileThrowsException() throws Exception {
    SignedDoc ddoc = Mockito.mock(SignedDoc.class);
    ArrayList<ee.sk.digidoc.DataFile> mockedDataFiles = new ArrayList<>();
    DataFile dataFile = Mockito.mock(DataFile.class);
    Mockito.when(dataFile.getFileName()).thenReturn("test.txt");
    mockedDataFiles.add(dataFile);
    Mockito.doReturn(mockedDataFiles).when(ddoc).getDataFiles();
    Mockito.doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).removeDataFile(Mockito.anyInt());
    DDocFacade facade = new DDocFacade(ddoc);
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.removeDataFile("test.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void containerWithFileNameThrowsException() throws Exception {
    this.openDDocFacade("file_not_exists");
  }

  @Test
  public void setsSignatureId() throws Exception {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureId("SIGNATURE-1");
    facade.setSignatureParameters(signatureParameters);
    facade.sign(this.pkcs12SignatureToken);
    signatureParameters.setSignatureId("SIGNATURE-2");
    facade.setSignatureParameters(signatureParameters);
    facade.sign(this.pkcs12SignatureToken);
    String file = this.getFileBy("ddoc");
    facade.save(file);
    facade = this.openDDocFacade(file);
    Assert.assertEquals("SIGNATURE-1", facade.getSignature(0).getId());
    Assert.assertEquals("SIGNATURE-2", facade.getSignature(1).getId());
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    DDocFacade container = new DDocFacade();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.sign(this.pkcs12SignatureToken);
    container.sign(this.pkcs12SignatureToken);
    String file = this.getFileBy("ddoc");
    container.save(file);
    container = this.openDDocFacade(file);
    Assert.assertEquals("S0", container.getSignature(0).getId());
    Assert.assertEquals("S1", container.getSignature(1).getId());
  }

  @Test
  public void setsSignatureIdWithoutOCSP() throws Exception {
    DDocFacade facade = new DDocFacade();
    facade.setSignatureProfile(SignatureProfile.B_BES);
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureId("SIGNATURE-1");
    facade.setSignatureParameters(signatureParameters);
    facade.sign(this.pkcs12SignatureToken);
    signatureParameters.setSignatureId("SIGNATURE-2");
    facade.setSignatureParameters(signatureParameters);
    facade.sign(this.pkcs12SignatureToken);
    String file = this.getFileBy("ddoc");
    facade.save(file);
    facade = this.openDDocFacade(file);
    Assert.assertEquals("SIGNATURE-1", facade.getSignature(0).getId());
    Assert.assertEquals("SIGNATURE-2", facade.getSignature(1).getId());
  }

  @Test
  public void setsDefaultSignatureIdWithoutOCSP() throws Exception {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.setSignatureProfile(SignatureProfile.B_BES);
    facade.sign(this.pkcs12SignatureToken);
    facade.sign(this.pkcs12SignatureToken);
    String file = this.getFileBy("ddoc");
    facade.save(file);
    facade = this.openDDocFacade(file);
    Assert.assertEquals("S0", facade.getSignature(0).getId());
    Assert.assertEquals("S1", facade.getSignature(1).getId());
  }

  @Test
  public void savesToStream() throws IOException {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.sign(this.pkcs12SignatureToken);
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      facade.save(out);
      Assert.assertTrue(out.size() != 0);
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void savesToStreamThrowsException() throws Exception {
    SignedDoc ddoc = Mockito.mock(SignedDoc.class);
    DigiDocException testException = new DigiDocException(100, "testException", new Throwable("test Exception"));
    Mockito.doThrow(testException).when(ddoc).writeToStream(Matchers.any(OutputStream.class));
    DDocFacade facade = new DDocFacade(ddoc);
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      facade.save(out);
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void openFromStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("src/test/resources/testFiles/helper-files/test.txt"));
    stream.close();
    new DDocOpener().open(stream);
  }

  @Test
  public void ddocStreamOpener() throws IOException {
    try (FileInputStream stream = new FileInputStream(
        new File("src/test/resources/testFiles/valid-containers/ddoc_wo_x509IssueName_xmlns.ddoc"))) {
      DDocContainer container = new DDocOpener().open(stream);
      Assert.assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void getSignatureByIndex() throws CertificateEncodingException {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.sign(this.pkcs12SignatureToken);
    facade.sign(this.pkcs12SignatureToken);
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c", facade.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test(expected = DigiDoc4JException.class)
  public void addDataFileAfterSigning() {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.sign(this.pkcs12SignatureToken);
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileAfterSigning() {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.sign(this.pkcs12SignatureToken);
    facade.removeDataFile("src/test/resources/testFiles/helper-files/test.txt");
  }

  @Test
  public void getSignatureWhenNotSigned() {
    Assert.assertTrue(new DDocFacade().getSignatures().isEmpty());
  }

  @Test(expected = NotSupportedException.class)
  public void timeStampProfileIsNotSupported() throws Exception {
    new DDocFacade().setSignatureProfile(SignatureProfile.LT);
  }

  @Test(expected = NotSupportedException.class)
  public void TSAProfileIsNotSupported() throws Exception {
    new DDocFacade().setSignatureProfile(SignatureProfile.LTA);
  }

  @Test(expected = NotSupportedException.class)
  public void timeStampProfileIsNotSupportedForExtension() throws Exception {
    DDocFacade facade = new DDocFacade();
    facade.setSignatureProfile(SignatureProfile.B_BES);
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.sign(this.pkcs12SignatureToken);
    facade.extendTo(SignatureProfile.LT);
  }

  @Test
  public void extendToTM() throws Exception {
    DDocFacade facade = new DDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.setSignatureProfile(SignatureProfile.B_BES);
    facade.sign(this.pkcs12SignatureToken);
    String file = this.getFileBy("ddoc");
    facade.save(file);
    facade = this.openDDocFacade(file);
    Assert.assertNull(facade.getSignature(0).getOCSPCertificate());
    facade.extendTo(SignatureProfile.LT_TM);
    file = this.getFileBy("ddoc");
    facade.save(file);
    facade = this.openDDocFacade(file);
    Assert.assertNotNull(facade.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extendToThrowsExceptionForGetConfirmation() throws Exception {
    MockDDocFacade facade = new MockDDocFacade();
    facade.setSignatureProfile(SignatureProfile.B_BES);
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.sign(this.pkcs12SignatureToken);
    facade.extendTo(SignatureProfile.LT_TM);
  }

  @Test
  public void getVersion() {
    Assert.assertEquals("1.3", new DDocFacade().getVersion());
  }

  @Test(expected = DigiDoc4JException.class)
  public void signThrowsException() throws Exception {
    DDocFacade facade = new MockDDocFacade();
    facade.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    facade.sign(this.pkcs12SignatureToken);
    facade.extendTo(SignatureProfile.LT_TM);
  }

  @Test
  public void twoStepSigning() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    SignedInfo info = container.prepareSigning(this.pkcs12SignatureToken.getCertificate());
    byte[] signature = this.sign(info.getDigestToSign(), DigestAlgorithm.SHA256);
    container.signRaw(signature);
    String file = this.getFileBy("ddoc");
    container.save(file);
    container = this.openContainerBy(Paths.get(file));
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void prepareSigningThrowsException() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.prepareSigning(null);
  }

  @Test(expected = DigiDoc4JException.class)
  public void signRawThrowsException() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.prepareSigning(this.pkcs12SignatureToken.getCertificate());
    container.signRaw(null);
  }

  @Test
  public void signExistingContainer() throws Exception {
    DDocFacade container = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.sign(this.pkcs12SignatureToken);
    Assert.assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void signRawWithLT_TMSignatureProfileAddsOCSP() {
    String file = this.getFileBy("ddoc");
    this.signRawDDocContainer(SignatureProfile.LT_TM).saveAsFile(file);
    Assert.assertNotNull(this.openContainerBy(Paths.get(file)).getSignatures().get(0).getOCSPCertificate());
  }

  @Test
  public void signRawWithNoSignatureProfileDoesNotAddOCSP() {
    String file = this.getFileBy("ddoc");
    this.signRawDDocContainer(SignatureProfile.B_BES).saveAsFile(file);
    Assert.assertNull(this.openContainerBy(Paths.get(file)).getSignatures().get(0).getOCSPCertificate());
  }

  @Test
  public void configManagerShouldBeInitializedOnlyOnce() throws Exception {
    DDocFacade.configManagerInitializer = new MockConfigManagerInitializer();
    Assert.assertFalse(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(0, MockConfigManagerInitializer.configManagerCallCount);
    new DDocFacade();
    Assert.assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
    new DDocFacade();
    Assert.assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
    this.openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
  }

  @Test(expected = ConfigurationException.class)
  public void openingDDoc_withoutCAConfiguration_shouldThrowException() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc"));
  }

  /*
   * RESTRICTED METHODS
   */

  private DDocFacade openDDocFacade(String path) {
    return new DDocOpener().open(path).getJDigiDocFacade();
  }

  private Container signRawDDocContainer(SignatureProfile signatureProfile) {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    container.setSignatureProfile(signatureProfile);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.signRaw(this.sign(container.prepareSigning(this.pkcs12SignatureToken.getCertificate()).getDigestToSign(),
        DigestAlgorithm.SHA256));
    return container;
  }

}
