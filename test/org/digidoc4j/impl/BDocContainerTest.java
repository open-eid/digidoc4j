package org.digidoc4j.impl;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.signature.token.Constants;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.signers.ExternalSigner;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.zip.ZipFile;

import static java.util.Arrays.asList;
import static org.digidoc4j.Container.DocumentType;
import static org.digidoc4j.Container.SignatureProfile.*;
import static org.digidoc4j.DigestAlgorithm.SHA1;
import static org.digidoc4j.DigestAlgorithm.SHA256;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class BDocContainerTest extends DigiDoc4JTestHelper {

  private PKCS12Signer PKCS12_SIGNER;

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test".toCharArray());
  }

  @AfterClass
  public static void deleteTemporaryFiles() {
    try {
      DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("."));
      for (Path item : directoryStream) {
        String fileName = item.getFileName().toString();
        if (fileName.endsWith("bdoc") && fileName.startsWith("test")) Files.deleteIfExists(item);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testSetDigestAlgorithmToSHA256() throws Exception {
    BDocContainer container = new BDocContainer();
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(SHA256);
    container.setSignatureParameters(signatureParameters);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.getDigestAlgorithm().toString());
  }

  @Test
  public void testSetDigestAlgorithmToSHA1() throws Exception {
    BDocContainer container = new BDocContainer();
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(SHA1);
    container.setSignatureParameters(signatureParameters);
    assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", container.getDigestAlgorithm().toString());
  }

  @Test
  public void testSetDigestAlgorithmToNotImplementedDigest() throws Exception {
    BDocContainer container = new BDocContainer();
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(SHA256);
    container.setSignatureParameters(signatureParameters);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.getDigestAlgorithm().toString());
  }

  @Test
  public void testDefaultDigestAlgorithm() throws Exception {
    BDocContainer container = new BDocContainer();
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.getDigestAlgorithm().toString());
  }

  @Test
  public void testOpenBDocDocument() throws Exception {
    BDocContainer container = new BDocContainer("testFiles/asics_for_testing.bdoc");
    container.verify();
  }

  @Test
  public void testOpenBDocDocumentWithTwoSignatures() throws Exception {
    BDocContainer container = new BDocContainer("testFiles/two_signatures.bdoc");
    container.verify();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileWhenFileDoesNotExist() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("notExisting.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileFromInputStreamWithByteArrayConversionFailure() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile(new MockInputStream(), "test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddRawSignature() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addRawSignature(new byte[]{});
  }

  @Test(expected = NotYetImplementedException.class)
  public void testAddRawSignatureFromInputStream() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addRawSignature(new ByteArrayInputStream(Signatures.XADES_SIGNATURE.getBytes()));
    container.save("test_add_raw_signature.bdoc");

    Container openedContainer = Container.open("test_add_raw_signature.bdoc");
    assertEquals(1, openedContainer.getSignatures().size());
  }

  @Test
  public void testSaveBDocDocumentWithTwoSignatures() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testTwoSignatures.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(1).getSigningCertificate().getSerial());

    Container openedContainer = Container.open("testTwoSignatures.bdoc");

    assertEquals(2, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(1).getSigningCertificate().getSerial());
  }

  @Test
  public void getSignatureByIndex() {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);

    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12", container.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test
  public void testAddSignaturesToExistingDocument() throws Exception {
    Container container = Container.open("testFiles/asics_testing_two_signatures.bdoc");
    container.sign(PKCS12_SIGNER);
    container.save("testAddMultipleSignatures.bdoc");

    assertEquals(3, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(2).getSigningCertificate().getSerial());

    Container openedContainer = Container.open("testAddMultipleSignatures.bdoc");

    assertEquals(3, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(2).getSigningCertificate().getSerial());

  }

  @Test
  public void testRemoveSignatureWhenOneSignatureExists() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.removeSignature(0);
    container.save("testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());

    container = new BDocContainer("testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() throws Exception {
    Container container = Container.open("testFiles/asics_testing_two_signatures.bdoc");
    container.removeSignature(0);
    container.save("testRemoveSignature.bdoc");

    container = new BDocContainer("testRemoveSignature.bdoc");
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenThreeSignaturesExist() throws Exception {
    Container container = Container.open("testFiles/asics_testing_two_signatures.bdoc");

    container.sign(PKCS12_SIGNER);
    container.save("testThreeSignatures.bdoc");
    container = new BDocContainer("testThreeSignatures.bdoc");
    assertEquals(3, container.getSignatures().size());

    container.removeSignature(1);

    container.save("testRemoveSignature.bdoc");

    container = new BDocContainer("testRemoveSignature.bdoc");
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void testSaveDocumentWithOneSignature() throws Exception {
    createSignedBDocDocument("testSaveBDocDocumentWithOneSignature.bdoc");
    assertTrue(Files.exists(Paths.get("testSaveBDocDocumentWithOneSignature.bdoc")));
  }

  @Test
  public void testVerifySignedDocument() throws Exception {
    BDocContainer container = (BDocContainer) createSignedBDocDocument("testSaveBDocDocumentWithOneSignature.bdoc");
    ValidationResult result = container.verify();
    assertFalse(result.hasErrors());
  }

  @Test
  public void testTestVerifyOnInvalidDocument() throws Exception {
    BDocContainer container = new BDocContainer("testFiles/invalid_container.bdoc");
    assertTrue(container.verify().hasErrors());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemoveDataFileAfterSigning() throws Exception {
    createSignedBDocDocument("testRemoveDataFile.bdoc");
    Container container = new BDocContainer("testRemoveDataFile.bdoc");
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testRemoveDataFile() throws Exception {
    Container container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("testFiles/test.txt");
    assertEquals(0, container.getDataFiles().size());
  }


  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileAfterSigning() throws Exception {
    createSignedBDocDocument("testAddDataFile.bdoc");
    Container container = new BDocContainer("testAddDataFile.bdoc");
    container.addDataFile("testFiles/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNonExistingFile() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.removeDataFile("test1.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingSameFileSeveralTimes() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingSameFileInDifferentContainerSeveralTimes() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/sub/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testAddSameFile.bdoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingNotExistingFile() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("notExistingFile.txt", "text/plain");
  }

  @Test
  public void testAddFileAsStream() throws Exception {
    BDocContainer container = new BDocContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testAddFileAsStream.bdoc");

    Container containerToTest = new BDocContainer("testAddFileAsStream.bdoc");
    assertEquals("test1.txt", containerToTest.getDataFiles().get(0).getName());
  }

  @Test
  public void setsSignatureId() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");

    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureId("SIGNATURE-1");
    container.setSignatureParameters(signatureParameters);
    container.sign(PKCS12_SIGNER);

    signatureParameters.setSignatureId("SIGNATURE-2");
    container.setSignatureParameters(signatureParameters);
    container.sign(PKCS12_SIGNER);
    container.save("setsSignatureId.bdoc");

    container = new BDocContainer("setsSignatureId.bdoc");
    assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    assertEquals("SIGNATURE-2", container.getSignature(1).getId());

    ZipFile zip = new ZipFile("setsSignatureId.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testSetsDefaultSignatureId.bdoc");

    container = new BDocContainer("testSetsDefaultSignatureId.bdoc");
    assertEquals("S0", container.getSignature(0).getId());
    assertEquals("S1", container.getSignature(1).getId());

    ZipFile zip = new ZipFile("testSetsDefaultSignatureId.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void getDataFileByIndex() {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    assertEquals("test.txt", container.getDataFile(0).getName());
  }

  @Test
  public void rawSignatureDoesNotThrowExceptionInCloseError() throws IOException {
    BDocContainer container = spy(new BDocContainer());
    byte[] signature = {0x41};
    MockInputStream value = new MockInputStream();

    doNothing().when(container).addRawSignature(value);
    when(container.getByteArrayInputStream(signature)).thenReturn(value);

    container.addRawSignature(signature);
  }


  @Test(expected = SignatureNotFoundException.class)
  public void testSignatureNotFoundException() throws Exception {
    BDocContainer container = new BDocContainer();
    BDocContainer spy = spy(container);

    eu.europa.ec.markt.dss.parameter.SignatureParameters signatureParameters =
        new eu.europa.ec.markt.dss.parameter.SignatureParameters();
    signatureParameters.setDeterministicId("NotPresentSignature");
    when(spy.getDssSignatureParameters()).thenReturn(signatureParameters);

    spy.addDataFile("testFiles/test.txt", "text/plain");
    spy.sign(PKCS12_SIGNER);
  }

  @Test(expected = DigiDoc4JException.class)
  public void openNonExistingFileThrowsError() {
    new BDocContainer("non-existing.bdoc");
  }


  @Test(expected = DigiDoc4JException.class)
  public void openClosedStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("testFiles/test.txt"));
    stream.close();
    new BDocContainer(stream, false);
  }

  @Test
  public void testLargeFileSigning() throws Exception {
    BDocContainer container = new BDocContainer();
    container.configuration.enableBigFilesSupport(10);
    String path = createLargeFile((container.configuration.getMaxDataFileCachedInBytes()) + 100);
    container.addDataFile(path, "text/plain");
    container.sign(PKCS12_SIGNER);
  }

  @Test
  public void openLargeFileFromStream() throws FileNotFoundException {

    BDocContainer container = new BDocContainer();
    container.configuration.enableBigFilesSupport(0);

    String path = createLargeFile((container.configuration.getMaxDataFileCachedInBytes()) + 100);
    container.addDataFile(path, "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("test-large-file.bdoc");
    File file = new File("test-large-file.bdoc");
    FileInputStream fileInputStream = new FileInputStream(file);
    Container.open(fileInputStream, true);

    IOUtils.closeQuietly(fileInputStream);

    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void openAddFileFromStream() throws IOException {
    BDocContainer container = new BDocContainer();
    container.configuration.enableBigFilesSupport(0);

    String path = createLargeFile((container.configuration.getMaxDataFileCachedInBytes()) + 100);
    try (FileInputStream stream = new FileInputStream(new File(path))) {
      container.addDataFile(stream, "fileName", "text/plain");
      container.sign(PKCS12_SIGNER);
      container.save("test-large-file.bdoc");
      File file = new File("test-large-file.bdoc");
      FileInputStream fileInputStream = new FileInputStream(file);
      Container.open(fileInputStream, true);
      IOUtils.closeQuietly(fileInputStream);
    }
    assertEquals(1, container.getSignatures().size());
  }

  private String createLargeFile(long size) {
    String fileName = "test_large_file.bdoc";
    try {
      RandomAccessFile largeFile = new RandomAccessFile(fileName, "rw");
      largeFile.setLength(size);//todo create large file correctly
    } catch (Exception e) {
      e.printStackTrace();
    }
    return fileName;
  }

  @Test
  public void testGetDocumentType() throws Exception {
    createSignedBDocDocument("testGetDocumentType.bdoc");
    BDocContainer container = new BDocContainer("testGetDocumentType.bdoc");
    assertEquals(DocumentType.BDOC, container.getDocumentType());
  }

  @Test
  public void testAddTwoFilesAsStream() throws Exception {
    BDocContainer container = new BDocContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.addDataFile(stream, "test2.txt", "text/plain");
  }

  @Test
  public void testAddTwoFilesAsFileWithoutOCSP() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    container.sign(PKCS12_SIGNER);
    container.save("testTwoFilesSigned.bdoc");

    container = new BDocContainer("testTwoFilesSigned.bdoc");
    assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void testGetFileNameAndID() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    container.sign(PKCS12_SIGNER);
    container.save("testTwoFilesSigned.bdoc");

    container = new BDocContainer("testTwoFilesSigned.bdoc");

    assertEquals("test.xml", container.getDataFile(0).getName());
    assertEquals("test.txt", container.getDataFile(1).getName());
    assertEquals("test.xml", container.getDataFile(0).getId());
    assertEquals("test.txt", container.getDataFile(1).getId());
  }

  @Test
  public void testAddTwoFilesAsFileWithOCSP() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    container.sign(PKCS12_SIGNER);
    container.save("testTwoFilesSigned.bdoc");

    container = new BDocContainer("testTwoFilesSigned.bdoc");
    assertEquals(2, container.getDataFiles().size());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testValidateEmptyDocument() {
    BDocContainer container = new BDocContainer();
    container.validate();
  }

  @Test
  public void testValidate() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    ValidationResult validationResult = container.validate();
    assertEquals(0, validationResult.getErrors().size());
  }

  @Test
  public void testLoadConfiguration() throws Exception {
    BDocContainer container = new BDocContainer();
    assertFalse(container.configuration.isBigFilesSupportEnabled());
    container.loadConfiguration("testFiles/digidoc_test_conf.yaml");
    assertTrue(container.configuration.isBigFilesSupportEnabled());
    assertEquals(8192, container.configuration.getMaxDataFileCachedInMB());
  }

  @Test
  public void saveToStream() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "test_bytes.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    File expectedContainerAsFile = new File("testSaveToStreamTest.bdoc");
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    container.save(out);
    assertTrue(Files.exists(expectedContainerAsFile.toPath()));

    Container containerToTest = Container.open(expectedContainerAsFile.getName());
    assertArrayEquals(new byte[]{0x42}, containerToTest.getDataFiles().get(0).getBytes());
  }

  @Test(expected = DigiDoc4JException.class)
  public void saveToStreamThrowsException() throws IOException {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    File expectedContainerAsFile = new File("testSaveToStreamTest.bdoc");
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    out.close();
    container.save(out);
  }

  @Test
  public void configurationImmutabilityWhenLoadingFromFile() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("test_immutable.bdoc");

    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    String tspSource = configuration.getTspSource();

    container = new BDocContainer("test_immutable.bdoc", configuration);
    configuration.setTspSource("changed_tsp_source");

    assertEquals(tspSource, container.configuration.getTspSource());
  }


  @Test
  public void TSLIsLoadedAfterSettingNewTSLLocation() {
    Configuration configuration = new Configuration();
    configuration.setTslLocation("file:test-tsl/trusted-test-mp.xml");
    BDocContainer container = new BDocContainer(configuration);
    container.configuration.getTSL();
    assertEquals(6, container.configuration.getTSL().getCertificates().size());

    configuration.setTslLocation("http://10.0.25.57/tsl/trusted-test-mp.xml");
    container = new BDocContainer(configuration);
    assertNotEquals(6, container.configuration.getTSL().getCertificates().size());
  }

  @Test
  public void extendToTS() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = new BDocContainer("testExtendTo.bdoc");
    container.extendTo(Container.SignatureProfile.TS);
    container.save("testExtendToContainsIt.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void verifySignatureProfileIsTS() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(Container.SignatureProfile.TS);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testAddConfirmation.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = NotYetImplementedException.class)
  public void signatureProfileTMIsNotSupported() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(TM);
  }

  @Test(expected = DigiDoc4JException.class)
  public void extendToWhenConfirmationAlreadyExists() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.setSignatureProfile(BES);
    container.sign(PKCS12_SIGNER);
    container.save("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = new BDocContainer("testExtendTo.bdoc");
    container.extendTo(TS);
    container.extendTo(TS);
  }

  @Test(expected = DigiDoc4JException.class)
  public void signWithoutDataFile() throws Exception {
    BDocContainer container = new BDocContainer();
    container.sign(PKCS12_SIGNER);
  }

  @Test
  public void extendToWithMultipleSignatures() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.setSignatureProfile(BES);
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testExtendTo.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());
    assertNull(container.getSignature(1).getOCSPCertificate());

    container = new BDocContainer("testExtendTo.bdoc");
    container.extendTo(TS);
    container.save("testExtendToContainsIt.bdoc");

    container = new BDocContainer("testExtendToContainsIt.bdoc");
    assertEquals(2, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
    assertNotNull(container.getSignature(1).getOCSPCertificate());
  }

  @Test(expected = NotYetImplementedException.class)
  public void extendToIsImplementedForTSProfileOtherProfilesThrowException() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.setSignatureProfile(BES);
    container.sign(PKCS12_SIGNER);

    container.extendTo(TM);
  }

  @Test
  public void extendToWithMultipleSignaturesAndMultipleFiles() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testAddConfirmation.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertEquals(2, container.getDataFiles().size());
    assertNull(container.getSignature(0).getOCSPCertificate());
    assertNull(container.getSignature(1).getOCSPCertificate());

    container = new BDocContainer("testAddConfirmation.bdoc");
    container.extendTo(TS);
    container.save("testAddConfirmationContainsIt.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertEquals(2, container.getDataFiles().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
    assertNotNull(container.getSignature(1).getOCSPCertificate());
  }

  @Test(expected = UnsupportedFormatException.class)
  public void notBDocThrowsException() {
    new BDocContainer("testFiles/notABDoc.bdoc");
  }

  @Test(expected = UnsupportedFormatException.class)
  public void incorrectMimetypeThrowsException() {
    new BDocContainer("testFiles/incorrectMimetype.bdoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void signingThrowsNormalDSSException() {
    MockBDocContainer container = new MockBDocContainer("Normal DSS Exception");
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signingThrowsOCSPException() {
    MockBDocContainer container = new MockBDocContainer("OCSP request failed");
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
  }

  @Test
  public void getVersion() {
    BDocContainer container = new BDocContainer();
    assertNull(container.getVersion());
  }

  @Test
  public void testContainerExtensionToTSA() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    container.extendTo(TSA);

    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void twoStepSigning() {
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

    Container container = Container.create();
    container.setSignatureParameters(signatureParameters);
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSignerCert();
    SignedInfo signedInfo = container.prepareSigning(signerCert);
    byte[] signature = getExternalSignature(container, signerCert, signedInfo);
    container.signRaw(signature);
    container.save("test.bdoc");

    container = Container.open("test.bdoc");
    assertEquals(1, container.getSignatures().size());
  }

  static byte[] getExternalSignature(Container container, final X509Certificate signerCert,
                                             SignedInfo prepareSigningSignature) {
    Signer externalSigner = new ExternalSigner(signerCert) {
      @Override
      public byte[] sign(Container container, byte[] dataToSign) {
        try {
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          try (FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
            keyStore.load(stream, "test".toCharArray());
          }
          PrivateKey privateKey = (PrivateKey) keyStore.getKey("1", "test".toCharArray());
          final String javaSignatureAlgorithm = "NONEwith" + privateKey.getAlgorithm();

          return DSSUtils.encrypt(javaSignatureAlgorithm, privateKey, addPadding(dataToSign));
        } catch (Exception e) {
          throw new DigiDoc4JException("Loading private key failed");
        }
      }

      private byte[] addPadding(byte[] digest) {
        return ArrayUtils.addAll(Constants.SHA512_DIGEST_INFO_PREFIX, digest);
      }
    };

    return externalSigner.sign(container, prepareSigningSignature.getDigest());
  }

  static X509Certificate getSignerCert() {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try (FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
        keyStore.load(stream, "test".toCharArray());
      }
      return (X509Certificate) keyStore.getCertificate("1");
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading signer cert failed");
    }
  }

  @Test
  @Ignore
  public void verifySerializationCompletesSuccessfully() throws Exception {
    Container container = Container.create();

    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
    signatureParameters.setRoles(asList("manager", "employee"));
    signatureParameters.setProductionPlace(new SignatureProductionPlace("city", "state", "postalCode", "country"));
    signatureParameters.setSignatureId("S0");

    container.setSignatureParameters(signatureParameters);

    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    container.setSignatureProfile(BES);

    X509Certificate signerCert = getSignerCert();

    SignedInfo signedInfo = container.prepareSigning(signerCert);

    serialize(container);

    byte[] signature = getExternalSignature(container, signerCert, signedInfo);

    Container deserializedContainer = deserializer();
    deserializedContainer.signRaw(signature);

    signatureParameters.setSignatureId("S1");
    signatureParameters.setProductionPlace(new SignatureProductionPlace("city2", "state2", "postalCode2", "country2"));
    deserializedContainer.setSignatureParameters(signatureParameters);
    signedInfo = deserializedContainer.prepareSigning(signerCert);

    signature = getExternalSignature(deserializedContainer, signerCert, signedInfo);

    deserializedContainer.signRaw(signature);
    deserializedContainer.save("deserializedContainer.bdoc");

    deserializedContainer.extendTo(TSA);
    deserializedContainer.validate();

    serialize(deserializedContainer);
    deserializedContainer = deserializer();

    container = Container.open("deserializedContainer.bdoc");
    ValidationResult validate = container.validate();

    verifySerializationContainer(container, validate);

    verifySerializationContainer(deserializedContainer, validate);
  }

  private void verifySerializationContainer(Container container, ValidationResult validate) {
    assertEquals(0, validate.getErrors().size());
    assertEquals(6, validate.getWarnings().size());

    assertEquals(2, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", resultSignature.getSignatureMethod());
    assertEquals("city", resultSignature.getCity());
    assertEquals("manager", resultSignature.getSignerRoles().get(0));
    assertEquals("employee", resultSignature.getSignerRoles().get(1));
    assertEquals("S0", resultSignature.getId());

    resultSignature = container.getSignature(1);
    assertEquals("city2", resultSignature.getCity());
    assertEquals("S1", resultSignature.getId());
  }

  private static void serialize(Container container) throws IOException {

    FileOutputStream fileOut = new FileOutputStream("container.bin");
    ObjectOutputStream out = new ObjectOutputStream(fileOut);
    out.writeObject(container);
    out.flush();
    out.close();
    fileOut.close();
  }

  private static Container deserializer() throws IOException, ClassNotFoundException {
    FileInputStream fileIn = new FileInputStream("container.bin");
    ObjectInputStream in = new ObjectInputStream(fileIn);

    Container container = (Container) in.readObject();

    in.close();
    fileIn.close();

    return container;
  }

  @Test
  public void testContainerCreationAsTSA() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(TSA);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extensionNotPossibleWhenSignatureLevelIsSame() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(TSA);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.extendTo(TSA);
  }

  private Container createSignedBDocDocument(String fileName) {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save(fileName);
    return container;
  }

  private class MockInputStream extends InputStream {

    public MockInputStream() {
    }

    @Override
    public int read() throws IOException {
      return 0;
    }

    @Override
    public int read(@SuppressWarnings("NullableProblems") byte b[], int off, int len) throws IOException {
      throw new IOException();
    }

    @Override
    public void close() throws IOException {
      throw new IOException();
    }
  }

  private class MockBDocContainer extends BDocContainer {
    private String expected;

    public MockBDocContainer(String expected) {
      super();
      this.expected = expected;
    }

    @Override
    public Signature sign(Signer signer) {
      super.asicService = spy(new ASiCService(new CommonCertificateVerifier()));
      doThrow(new DSSException(expected)).when(super.asicService).signDocument(Mockito.any(DSSDocument.class),
          Mockito.any(eu.europa.ec.markt.dss.parameter.SignatureParameters.class), Mockito.any(byte[].class));
      return super.sign(signer);
    }
  }
}