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

import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;
import static org.digidoc4j.DigestAlgorithm.SHA1;
import static org.digidoc4j.DigestAlgorithm.SHA224;
import static org.digidoc4j.DigestAlgorithm.SHA256;
import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.SignatureProfile.LT_TM;
import static org.digidoc4j.testutils.TestSigningHelper.getSigningCert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureContainer;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

public class DDocFacadeTest {
  public static final String TEXT_MIME_TYPE = "text/plain";
  private PKCS12SignatureToken PKCS12_SIGNER;

  @BeforeClass
  public static void setTestMode() {
    System.setProperty("digidoc4j.mode", "TEST");
  }

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray());
  }

  @AfterClass
  public static void deleteTemporaryFiles() {
    try {
      DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("."));
      for (Path item : directoryStream) {
        String fileName = item.getFileName().toString();
        if (fileName.endsWith("ddoc") && fileName.startsWith("test")) Files.deleteIfExists(item);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void testSaveThrowsException() throws Exception {
    DDocFacade container = new DDocFacade();
    container.save("/not/existing/path/testSaveThrowsException.ddoc");
  }

  @Test
  public void testGetDataFileSize() {
    DDocFacade container = openDocFacade("testFiles/ddoc_for_testing.ddoc");
    org.digidoc4j.DataFile dataFile = container.getDataFile(0);
    assertEquals(16, dataFile.getFileSize());
  }

  @Test
  public void testSetDigestAlgorithmSHA1() throws Exception {
    DDocFacade container = new DDocFacade();
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(SHA1);
    container.setSignatureParameters(signatureParameters);
  }

  @Test(expected = NotSupportedException.class)
  public void testSetDigestAlgorithmOtherThenSHA1() throws Exception {
    DDocFacade container = new DDocFacade();
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(SHA224);
    container.setSignatureParameters(signatureParameters);
  }

  @Test
  public void testCanAddTwoDataFilesWithSameName() throws Exception {
    DDocFacade dDocContainer = new DDocFacade();
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.save("test_ddoc_file.ddoc");
    Container container = ContainerOpener.open("test_ddoc_file.ddoc");
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();
    assertEquals(2, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getName());
    assertEquals("test.txt", dataFiles.get(1).getName());
  }

  @Test
  public void testGetFileId() {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();

    assertEquals("D0", dataFiles.get(0).getId());
    assertEquals("D1", dataFiles.get(1).getId());
    assertEquals("test.txt", dataFiles.get(0).getName());
    assertEquals("test.txt", dataFiles.get(1).getName());
  }

  @Test
  public void testAddEmptyFile() throws Exception {
    DDocFacade dDocContainer = new DDocFacade();
    //noinspection ResultOfMethodCallIgnored
    new File("test_empty.txt").createNewFile();
    dDocContainer.addDataFile("test_empty.txt", TEXT_MIME_TYPE);
    dDocContainer.save("test_empty.ddoc");
    Container container = ContainerOpener.open("test_empty.ddoc");
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals(0, dataFiles.get(0).getFileSize());

    Files.deleteIfExists(Paths.get("test_empty.txt"));
  }

  @Test
  public void getDataFileByIndex() {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.addDataFile("testFiles/test.xml", TEXT_MIME_TYPE);

    assertEquals("D0", container.getDataFile(0).getId());
    assertEquals("D1", container.getDataFile(1).getId());
    assertEquals("test.txt", container.getDataFile(0).getName());
    assertEquals("test.xml", container.getDataFile(1).getName());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddFileFromStreamToDDocThrowsException() throws DigiDocException, IOException {
    SignedDoc ddoc = mock(SignedDoc.class);
    when(ddoc.getNewDataFileId()).thenReturn("A");
    when(ddoc.getFormat()).thenReturn("SignedDoc.FORMAT_DDOC");
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(any(ee.sk.digidoc.DataFile.class));

    DDocFacade container = new DDocFacade(ddoc);
    try(ByteArrayInputStream is = new ByteArrayInputStream(new byte[]{0x42})) {
      container.addDataFile(is, "testFromStream.txt", TEXT_MIME_TYPE);
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileThrowsException() throws Exception {
    SignedDoc ddoc = mock(SignedDoc.class);
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(any(File.class), any(String.class), any(String.class));

    DDocFacade container = new DDocFacade(ddoc);
    container.addDataFile("testFiles/test.txt", "");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testGetDataFileThrowsException() throws Exception {
    SignedDoc ddoc = spy(new SignedDoc("DIGIDOC-XML", "1.3"));

    ee.sk.digidoc.DataFile dataFile = mock(ee.sk.digidoc.DataFile.class);
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(dataFile).getBody();
    ArrayList<ee.sk.digidoc.DataFile> mockedDataFiles = new ArrayList<>();
    mockedDataFiles.add(dataFile);
    doReturn(mockedDataFiles).when(ddoc).getDataFiles();

    DDocFacade container = new DDocFacade(ddoc);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.getDataFiles();
  }

  @Test
  public void testGetDataFilesWhenNoDataFileExists() {
    DDocFacade container = new DDocFacade();
    assertTrue(container.getDataFiles().isEmpty());
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileWhenNotFound() throws Exception {
    DDocFacade dDocContainer = new DDocFacade();
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.removeDataFile("NotThere.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileThrowsException() throws Exception {
    SignedDoc ddoc = mock(SignedDoc.class);

    ArrayList<ee.sk.digidoc.DataFile> mockedDataFiles = new ArrayList<>();
    DataFile dataFile = mock(DataFile.class);
    when(dataFile.getFileName()).thenReturn("test.txt");
    mockedDataFiles.add(dataFile);
    doReturn(mockedDataFiles).when(ddoc).getDataFiles();

    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).removeDataFile(anyInt());

    DDocFacade container = new DDocFacade(ddoc);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.removeDataFile("test.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void containerWithFileNameThrowsException() throws Exception {
    openDocFacade("file_not_exists");
  }

  @Test
  public void setsSignatureId() throws Exception {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", "text/plain");
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureId("SIGNATURE-1");
    container.setSignatureParameters(signatureParameters);
    container.sign(PKCS12_SIGNER);
    signatureParameters.setSignatureId("SIGNATURE-2");
    container.setSignatureParameters(signatureParameters);
    container.sign(PKCS12_SIGNER);
    container.save("setsSignatureId.ddoc");

    container = openDocFacade("setsSignatureId.ddoc");
    assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    assertEquals("SIGNATURE-2", container.getSignature(1).getId());
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testSetsDefaultSignatureId.ddoc");

    container = openDocFacade("testSetsDefaultSignatureId.ddoc");
    assertEquals("S0", container.getSignature(0).getId());
    assertEquals("S1", container.getSignature(1).getId());
  }

  @Test
  public void setsSignatureIdWithoutOCSP() throws Exception {
    DDocFacade container = new DDocFacade();
    container.setSignatureProfile(B_BES);

    container.addDataFile("testFiles/test.txt", "text/plain");
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureId("SIGNATURE-1");
    container.setSignatureParameters(signatureParameters);

    container.sign(PKCS12_SIGNER);
    signatureParameters.setSignatureId("SIGNATURE-2");
    container.setSignatureParameters(signatureParameters);
    container.sign(PKCS12_SIGNER);
    container.save("testSetsSignatureId.ddoc");

    container = openDocFacade("testSetsSignatureId.ddoc");
    assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    assertEquals("SIGNATURE-2", container.getSignature(1).getId());
  }

  @Test
  public void setsDefaultSignatureIdWithoutOCSP() throws Exception {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.setSignatureProfile(B_BES);
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testSetsDefaultSignatureId.ddoc");

    container = openDocFacade("testSetsDefaultSignatureId.ddoc");
    assertEquals("S0", container.getSignature(0).getId());
    assertEquals("S1", container.getSignature(1).getId());
  }

  @Test
  public void savesToStream() throws IOException {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);

    try(ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      container.save(out);
      assertTrue(out.size() != 0);
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void savesToStreamThrowsException() throws Exception {
    SignedDoc ddoc = mock(SignedDoc.class);
    DigiDocException testException = new DigiDocException(100, "testException", new Throwable("test Exception"));
    doThrow(testException).when(ddoc).writeToStream(any(OutputStream.class));

    DDocFacade container = new DDocFacade(ddoc);
    try(ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      container.save(out);
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void openFromStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("testFiles/test.txt"));
    stream.close();
    new DDocOpener().open(stream);
  }

  @Test
  public void getSignatureByIndex() throws CertificateEncodingException {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);

    assertEquals("530be41bbc597c44570e2b7c13bcfa0c", container.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test(expected = DigiDoc4JException.class)
  public void addDataFileAfterSigning() {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    container.addDataFile("testFiles/test.xml", TEXT_MIME_TYPE);
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileAfterSigning() {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    container.removeDataFile("testFiles/test.txt");
  }

  @Test
  public void getSignatureWhenNotSigned() {
    DDocFacade container = new DDocFacade();
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test(expected = NotSupportedException.class)
  public void timeStampProfileIsNotSupported() throws Exception {
    DDocFacade container = new DDocFacade();
    container.setSignatureProfile(LT);
  }

  @Test(expected = NotSupportedException.class)
  public void TSAProfileIsNotSupported() throws Exception {
    DDocFacade container = new DDocFacade();
    container.setSignatureProfile(LTA);
  }

  @Test(expected = NotSupportedException.class)
  public void timeStampProfileIsNotSupportedForExtension() throws Exception {
    DDocFacade container = new DDocFacade();
    container.setSignatureProfile(B_BES);
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    container.extendTo(LT);
  }

  @Test
  public void extendToTM() throws Exception {
    DDocFacade container = new DDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.setSignatureProfile(B_BES);
    container.sign(PKCS12_SIGNER);
    container.save("testAddConfirmation.ddoc");
    container = open("testAddConfirmation.ddoc");
    assertNull(container.getSignature(0).getOCSPCertificate());

    container.extendTo(LT_TM);
    container.save("testAddedConfirmation.ddoc");
    container = open("testAddedConfirmation.ddoc");
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extendToThrowsExceptionForGetConfirmation() throws Exception {
    MockDDocFacade container = new MockDDocFacade();
    container.setSignatureProfile(B_BES);
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);

    container.sign(PKCS12_SIGNER);

    container.extendTo(LT_TM);
  }

  @Test
  public void getVersion() {
    DDocFacade container = new DDocFacade();
    assertEquals("1.3", container.getVersion());
  }

  @Test(expected = DigiDoc4JException.class)
  public void signThrowsException() throws Exception {
    MockDDocFacade container = new MockDDocFacade();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);

    container.sign(PKCS12_SIGNER);

    container.extendTo(LT_TM);
  }

  @Test
  public void twoStepSigning() {
    Container container = createDDoc();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSigningCert();
    SignedInfo signedInfo = container.prepareSigning(signerCert);
    byte[] signature = getExternalSignature(signedInfo, SHA256);
    container.signRaw(signature);
    container.save("test.ddoc");

    container = ContainerOpener.open("test.ddoc");
    assertEquals(1, container.getSignatures().size());
  }

  @Test (expected = DigiDoc4JException.class)
  public void prepareSigningThrowsException() {
    Container container = createDDoc();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.prepareSigning(null);
  }

  @Test (expected = DigiDoc4JException.class)
  public void signRawThrowsException() {
    Container container = createDDoc();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSigningCert();
    container.prepareSigning(signerCert);

    container.signRaw(null);
  }

  @Test
  public void signExistingContainer() throws Exception {
    DDocFacade container = openDocFacade("testFiles/ddoc_for_testing.ddoc");
    container.sign(PKCS12_SIGNER);
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void signRawWithLT_TMSignatureProfileAddsOCSP() {
    String dDocFileName = "testOCSPAddedWithRawSignature.ddoc";
    signRawDDocContainer(LT_TM).saveAsFile(dDocFileName);
    assertNotNull(ContainerOpener.<SignatureContainer>open(dDocFileName).getSignatures().get(0).getOCSPCertificate());
  }

  @Test
  public void signRawWithNoSignatureProfileDoesNotAddOCSP() {
    String dDocFileName = "testOCSPNotAddedWithRawSignatureWhenNoProfile.ddoc";
    signRawDDocContainer(B_BES).saveAsFile(dDocFileName);
    assertNull(ContainerOpener.<SignatureContainer>open(dDocFileName).getSignatures().get(0).getOCSPCertificate());
  }

  @Test
  public void configManagerShouldBeInitializedOnlyOnce() throws Exception {
    DDocFacade.configManagerInitializer = new ConfigManagerInitializerSpy();
    assertFalse(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(0, ConfigManagerInitializerSpy.configManagerCallCount);
    DDocFacade container1 = new DDocFacade();
    assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(1, ConfigManagerInitializerSpy.configManagerCallCount);
    DDocFacade container2 = new DDocFacade();
    assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(1, ConfigManagerInitializerSpy.configManagerCallCount);
    String path = "testFiles/ddoc_for_testing.ddoc";
    DDocFacade container3 = openDocFacade(path);
    assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(1, ConfigManagerInitializerSpy.configManagerCallCount);
  }

  @Test (expected = ConfigurationException.class)
  public void openingDDoc_withoutCAConfiguration_shouldThrowException() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.loadConfiguration("testFiles/digidoc_test_conf_no_ca.yaml");
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    ContainerOpener.open("testFiles/ddoc_for_testing.ddoc", configuration);
  }

  private DDocFacade openDocFacade(String path) {
    return new DDocOpener().open(path).getJDigiDocFacade();
  }

  private Container signRawDDocContainer(SignatureProfile signatureProfile) {
    Container container = createDDoc();
    container.setSignatureProfile(signatureProfile);
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    X509Certificate signerCert = getSigningCert();
    SignedInfo signedInfo = container.prepareSigning(signerCert);
    byte[] signature = getExternalSignature(signedInfo, SHA256);
    container.signRaw(signature);
    return container;
  }

  private byte[] getExternalSignature(SignedInfo signedInfo, DigestAlgorithm digestAlgorithm) {
    return TestSigningHelper.sign(signedInfo.getDigestToSign(), digestAlgorithm);
  }

  private Container createDDoc() {
    return ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        build();
  }

  private DDocFacade open(String path) {
    DDocContainer container = (DDocContainer)ContainerOpener.open(path);
    return container.getJDigiDocFacade();
  }

  private class MockDDocFacade extends DDocFacade {
    ee.sk.digidoc.Signature signature = spy(new ee.sk.digidoc.Signature(new SignedDoc()));

    @Override
    public void extendTo(SignatureProfile profile) {
      super.ddoc = spy(new SignedDoc());
      getConfirmationThrowsException();
      doReturnSignatureList();

      super.extendTo(profile);
    }

    @Override
    ee.sk.digidoc.Signature calculateSignature(SignatureToken signatureToken) {
      return signature;
    }

    @Override
    public Signature sign(SignatureToken signatureToken) {
      super.ddoc = spy(new SignedDoc());
      ddocSignature = mock(ee.sk.digidoc.Signature.class);
      doReturnSignatureList();

      try {
        doReturn("A".getBytes()).when(ddocSignature).calculateSignedInfoXML();
      } catch (DigiDocException ignored) {}
      getConfirmationThrowsException();
      return super.sign(signatureToken);
    }

    private void getConfirmationThrowsException() {
      try {
        doThrow(new DigiDocException(1, "test", new Throwable())).when(signature).getConfirmation();
      } catch (DigiDocException e) {
        e.printStackTrace();
      }
    }

    private void doReturnSignatureList() {
      ArrayList<ee.sk.digidoc.Signature> signatures = new ArrayList<>();
      signatures.add(signature);
      doReturn(signatures).when(ddoc).getSignatures();
    }
  }

  private static class ConfigManagerInitializerSpy extends ConfigManagerInitializer {
    static int configManagerCallCount = 0;
    static {
      configManagerInitialized = false;
    }

    @Override
    void initializeJDigidocConfigManager(Configuration configuration) {
      super.initializeJDigidocConfigManager(configuration);
      configManagerCallCount++;
    }
  }
}
