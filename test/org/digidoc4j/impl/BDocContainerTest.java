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

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.signature.token.Constants;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.signers.ExternalSigner;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.*;
import org.digidoc4j.utils.Helper;
import org.mockito.Mockito;

import java.io.*;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipFile;

import static java.util.Arrays.asList;
import static org.digidoc4j.Container.*;
import static org.digidoc4j.Container.SignatureProfile.*;
import static org.digidoc4j.DigestAlgorithm.SHA1;
import static org.digidoc4j.DigestAlgorithm.SHA256;
import static org.digidoc4j.EncryptionAlgorithm.ECDSA;
import static org.digidoc4j.utils.Helper.deserializer;
import static org.digidoc4j.utils.Helper.serialize;
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
    BDocContainer container = new BDocContainer("testFiles/one_signature.bdoc");
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

    Container openedContainer = open("test_add_raw_signature.bdoc");
    assertEquals(1, openedContainer.getSignatures().size());
  }

  @Test
  public void testAddUnknownFileTypeKeepsMimeType() {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.unknown_type", "text/test_type");
    container.sign(PKCS12_SIGNER);
    container.save("test_add_unknown_datafile_type.bdoc");

    Container open = Container.open("test_add_unknown_datafile_type.bdoc");
    assertEquals(open.getDataFile(0).getMediaType(), "text/test_type");
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

    Container openedContainer = open("testTwoSignatures.bdoc");

    assertEquals(2, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(1).getSigningCertificate().getSerial());
  }

  @Test
  public void testGetDefaultSignatureParameters() {
    Container container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("test.bdoc");

    container = open("test.bdoc");
    Signature signature = container.getSignature(0);
    assertNull(signature.getPostalCode());
    assertNull(signature.getCity());
    assertNull(signature.getStateOrProvince());
    assertNull(signature.getCountryName());
    assertNull(signature.getSignerRoles());
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
  public void notThrowingNPEWhenDOCXFileIsAddedToContainer() {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/word_file.docx", "text/xml");
    container.sign(PKCS12_SIGNER);
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testAddSignaturesToExistingDocument() throws Exception {
    Container container = open("testFiles/asics_testing_two_signatures.bdoc");
    container.sign(PKCS12_SIGNER);
    container.save("testAddMultipleSignatures.bdoc");

    assertEquals(3, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(2).getSigningCertificate().getSerial());

    Container openedContainer = open("testAddMultipleSignatures.bdoc");

    assertEquals(3, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(2).getSigningCertificate().getSerial());

    ValidationResult validationResult = openedContainer.validate();
    assertEquals(0, validationResult.getErrors().size());
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
    public void testAddFilesWithSpecialCharactersIntoContainer() throws Exception {
        BDocContainer container = new BDocContainer();
        container.addDataFile("testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt", "text/plain");
        container.addDataFile("testFiles/special-char-files/dds_колючей стерне.docx", "text/plain");
        container.sign(PKCS12_SIGNER);
        container.save("testWithSpecialCharFiles.bdoc");

        assertEquals(0, container.verify().getContainerErrors().size());
    }

    @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() throws Exception {
    Container container = open("testFiles/asics_testing_two_signatures.bdoc");
    container.removeSignature(0);
    container.save("testRemoveSignature.bdoc");

    container = new BDocContainer("testRemoveSignature.bdoc");
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenThreeSignaturesExist() throws Exception {
    Container container = open("testFiles/asics_testing_two_signatures.bdoc");

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
  public void testAddingSamePreCreatedFileSeveralTimes() {
    BDocContainer container = new BDocContainer();
    DataFile dataFile = new DataFile("Hello world!".getBytes(), "test-file.txt", "text/plain");
    container.addDataFile(dataFile);
    container.addDataFile(dataFile);
  }

  @Test
  public void testAddingDifferentPreCreatedFiles() {
    BDocContainer container = new BDocContainer();
    container.addDataFile(new DataFile("Hello world!".getBytes(), "hello.txt", "text/plain"));
    container.addDataFile(new DataFile("Goodbye world!".getBytes(), "goodbye.txt", "text/plain")); 
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingSameFileSeveralTimesViaInputStream() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "testFiles/test.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "testFiles/test.txt", "text/plain");
  }

  @Test
  public void testAddDateFileViaInputStream() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    assertTrue(container.validate().isValid());
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
    open(fileInputStream, true);

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
      open(fileInputStream, true);
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
    container.setSignatureProfile(B_BES);
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

    Container containerToTest = open(expectedContainerAsFile.getName());
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
  @Ignore("RIA VPN")
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

  @Test (expected = DigiDoc4JException.class)
  public void TSLFileNotFoundThrowsException() {
    Configuration configuration = new Configuration();
    configuration.setTslLocation("file:test-tsl/NotExisting.xml");
    BDocContainer container = new BDocContainer(configuration);
    container.configuration.getTSL();
  }

  @Test (expected = DigiDoc4JException.class)
  public void TSLConnectionFailureThrowsException() {
    Configuration configuration = new Configuration();
    configuration.setTslLocation("http://127.0.0.1/tsl/incorrect.xml");
    BDocContainer container = new BDocContainer(configuration);
    container.configuration.getTSL();
  }

  @Test (expected = DigiDoc4JException.class)
  @Ignore // Not running by default to prevent system admin from getting worried
  public void TSLConnectionFailureIncorrectFileName() {
    Configuration configuration = new Configuration();
    configuration.setTslLocation("http://10.0.25.57/tsl/incorrect.xml");
    BDocContainer container = new BDocContainer(configuration);
    container.configuration.getTSL();
  }

  @Test
  public void extendFromB_BESToTS() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(B_BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = new BDocContainer("testExtendTo.bdoc");
    container.extendTo(SignatureProfile.LT);
    container.save("testExtendToContainsIt.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void extendFromB_BESToLTA() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(B_BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = new BDocContainer("testExtendTo.bdoc");
    container.extendTo(SignatureProfile.LTA);
    container.save("testExtendToContainsIt.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test (expected = DigiDoc4JException.class)
  public void extendFromB_BESToLT_TMThrowsException() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(B_BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.extendTo(SignatureProfile.LT_TM);
  }

  @Test (expected = DigiDoc4JException.class)
  public void extendFromLTToLT_TMThrowsException() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(LT);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.extendTo(SignatureProfile.LT_TM);
  }

  @Test (expected = DigiDoc4JException.class)
  public void extendFromLTAToLT_TMThrowsException() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(LTA);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.extendTo(SignatureProfile.LT_TM);
  }

  @Test
  public void containerIsLT() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(SignatureProfile.LT);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testLT.bdoc");

    container = new BDocContainer("testLT.bdoc");
    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void verifySignatureProfileIsTS() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(SignatureProfile.LT);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testAddConfirmation.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extendToWhenConfirmationAlreadyExists() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.setSignatureProfile(B_BES);
    container.sign(PKCS12_SIGNER);
    container.save("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = new BDocContainer("testExtendTo.bdoc");
    container.extendTo(LT);
    container.extendTo(LT);
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
    container.setSignatureProfile(B_BES);
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testExtendTo.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());
    assertNull(container.getSignature(1).getOCSPCertificate());

    container = new BDocContainer("testExtendTo.bdoc");
    container.extendTo(LT);
    container.save("testExtendToContainsIt.bdoc");

    container = new BDocContainer("testExtendToContainsIt.bdoc");
    assertEquals(2, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
    assertNotNull(container.getSignature(1).getOCSPCertificate());
  }

  @Test
  public void extendToWithMultipleSignaturesAndMultipleFiles() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(B_BES);
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
    container.extendTo(LT);
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

  @Test
  public void nonStandardMimeType() {
    Container container = Container.create(DocumentType.BDOC);
    container.addDataFile("testFiles/test.txt", "text/newtype");
    container.sign(PKCS12_SIGNER);
    container.save("testNonStandardMimeType.bdoc");
    container = Container.open("testNonStandardMimeType.bdoc");
    ValidationResult result = container.validate();
    assertEquals(0, result.getErrors().size());
    assertEquals("text/newtype", container.getDataFile(0).getMediaType());
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
  public void testContainerExtensionFromLTtoLTA() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    container.extendTo(LTA);
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void twoStepSigning() throws IOException {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSignerCert();
    SignedInfo signedInfo = container.prepareSigning(signerCert);
    byte[] signature = getExternalSignature(container, signerCert, signedInfo, SHA256);
    container.signRaw(signature);
    container.save("test.bdoc");

    container = open("test.bdoc");

    assertEquals(SHA256, container.getDigestAlgorithm());
    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());

    assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", resultSignature.getSignatureMethod());
    assertNull(resultSignature.getSignerRoles());
    assertNull(resultSignature.getCity());
    assertEquals("S0", resultSignature.getId());

    assertNotNull(resultSignature.getOCSPCertificate());
    assertNotNull(resultSignature.getSigningCertificate());
    assertNotNull(resultSignature.getRawSignature().length);
    assertEquals(LT, resultSignature.getProfile());
    assertNotNull(resultSignature.getTimeStampTokenCertificate());

    List<DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    DataFile dataFile = dataFiles.get(0);
    assertEquals("test.txt", dataFile.getName());
    dataFile.calculateDigest(DigestAlgorithm.SHA384);
    assertEquals("text/plain", dataFile.getMediaType());
    assertEquals(new String(Files.readAllBytes(Paths.get("testFiles/test.txt"))), new String(dataFile.getBytes()));
    assertEquals(15, dataFile.getFileSize());
    assertEquals("test.txt", dataFile.getId());
  }

  @Test
  public void twoStepSigningVerifySignatureParameters() {
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
    signatureParameters.setRoles(asList("manager", "employee"));
    signatureParameters.setProductionPlace(new SignatureProductionPlace("city", "state", "postalCode", "country"));
    signatureParameters.setSignatureId("S99");

    Container container = create();
    container.setSignatureParameters(signatureParameters);
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSignerCert();
    SignedInfo signedInfo = container.prepareSigning(signerCert);
    byte[] signature = getExternalSignature(container, signerCert, signedInfo,
        signatureParameters.getDigestAlgorithm());
    container.signRaw(signature);
    container.save("test.bdoc");

    container = open("test.bdoc");
    assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", resultSignature.getSignatureMethod());
    assertEquals("employee", resultSignature.getSignerRoles().get(1));
    assertEquals("city", resultSignature.getCity());
    assertEquals("S99", resultSignature.getId());
  }

  @Test
  public void twoStepSigningWithSerialization() throws IOException, ClassNotFoundException {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSignerCert();
    SignedInfo signedInfo = container.prepareSigning(signerCert);

    serialize(container, "container.bin");
    byte[] signature = getExternalSignature(container, signerCert, signedInfo, SHA256);

    container = deserializer("container.bin");
    container.signRaw(signature);
    container.save("test.bdoc");

    container = open("test.bdoc");

    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());

    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testContainerCreationAsTSA() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(LTA);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extensionNotPossibleWhenSignatureLevelIsSame() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(LTA);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.extendTo(LTA);
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

  static byte[] getExternalSignature(Container container, final X509Certificate signerCert,
                                     SignedInfo prepareSigningSignature, final DigestAlgorithm digestAlgorithm) {
    return getExternalSignature(container, signerCert, prepareSigningSignature, digestAlgorithm, "testFiles/signout.p12");
  }

  private static byte[] getExternalSignature(Container container, final X509Certificate signerCert,
                                             SignedInfo prepareSigningSignature, final DigestAlgorithm digestAlgorithm, final String signerCertFile) {
    Signer externalSigner = new ExternalSigner(signerCert) {
      @Override
      public byte[] sign(Container container, byte[] dataToSign) {
        try {
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          try (FileInputStream stream = new FileInputStream(signerCertFile)) {
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
        byte[] signatureDigest;
        switch (digestAlgorithm) {
          case SHA512:
            signatureDigest = Constants.SHA512_DIGEST_INFO_PREFIX;
            break;
          case SHA256:
            signatureDigest = Constants.SHA256_DIGEST_INFO_PREFIX;
            break;
          default:
            throw new NotYetImplementedException();
        }
        return ArrayUtils.addAll(signatureDigest, digest);
      }
    };

    return externalSigner.sign(container, prepareSigningSignature.getDigest());
  }

  static X509Certificate getSignerCert(String certFile) {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try (FileInputStream stream = new FileInputStream(certFile)) {
        keyStore.load(stream, "test".toCharArray());
      }
      return (X509Certificate) keyStore.getCertificate("1");
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading signer cert failed");
    }
  }

  static X509Certificate getSignerCert() {
    return getSignerCert("testFiles/signout.p12");
  }

  @Test
  public void verifySerialization() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    serialize(container, "container.bin");

    Container deserializedContainer = deserializer("container.bin");

    assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializationVerifySpecifiedSignatureParameters() throws Exception {
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
    signatureParameters.setRoles(asList("manager", "employee"));
    signatureParameters.setProductionPlace(new SignatureProductionPlace("city", "state", "postalCode", "country"));
    signatureParameters.setSignatureId("S99");

    Container container = create();
    container.setSignatureParameters(signatureParameters);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    serialize(container, "container.bin");

    Container deserializedContainer = deserializer("container.bin");

    Signature signature = deserializedContainer.getSignature(0);
    assertEquals("postalCode", signature.getPostalCode());
    assertEquals("city", signature.getCity());
    assertEquals("state", signature.getStateOrProvince());
    assertEquals("country", signature.getCountryName());
    assertEquals("employee", signature.getSignerRoles().get(1));
    assertEquals("S99", signature.getId());
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", signature.getSignatureMethod());
  }

  @Test
  public void serializationVerifyDefaultSignatureParameters() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    Signature signature = deserializedContainer.getSignature(0);

    assertNull(signature.getCity());
    assertNull(signature.getSignerRoles());
    assertEquals("S0", signature.getId());
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
  }

  @Test
  public void serializationGetDigestAlgorithm() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    assertEquals(SHA256, deserializedContainer.getDigestAlgorithm());
  }

  @Test
  public void serializationGetDocumentType() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    assertEquals(container.getDocumentType(), deserializedContainer.getDocumentType());
  }

  @Test
  public void serializationGetOCSPCertificate() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    byte[] ocspCertBeforeSerialization = container.getSignature(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    byte[] ocspCertAfterSerialization = deserializedContainer.getSignature(0).getOCSPCertificate().
        getX509Certificate().getEncoded();

    assertArrayEquals(ocspCertBeforeSerialization, ocspCertAfterSerialization);
  }

  @Test
  public void serializationGetSigningTime() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    Date signingTimeBeforeSerialization = container.getSignature(0).getSigningTime();
    Date signingTimeAfterSerialization = deserializedContainer.getSignature(0).getSigningTime();

    assertEquals(signingTimeBeforeSerialization, signingTimeAfterSerialization);
  }

  @Test(expected = NotYetImplementedException.class)
  public void serializationGetPolicy() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    String signaturePolicyBeforeSerialization = container.getSignature(0).getPolicy();
    String signaturePolicyAfterSerialization = deserializedContainer.getSignature(0).getPolicy();

    assertEquals(signaturePolicyBeforeSerialization, signaturePolicyAfterSerialization);
  }

  @Test(expected = NotYetImplementedException.class)
  public void serializationGetSignaturePolicyURI() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    URI signaturePolicyURIBeforeSerialization = container.getSignature(0).getSignaturePolicyURI();
    URI signaturePolicyURIAfterSerialization = deserializedContainer.getSignature(0).getSignaturePolicyURI();

    assertEquals(signaturePolicyURIBeforeSerialization, signaturePolicyURIAfterSerialization);
  }

  @Test
  public void serializationGetSigningCertificate() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    byte[] signingCertBeforeSerialization = container.getSignature(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    byte[] singingCertAfterSerialization = deserializedContainer.getSignature(0).getSigningCertificate().
        getX509Certificate().getEncoded();

    assertArrayEquals(signingCertBeforeSerialization, singingCertAfterSerialization);
  }

  @Test
  public void serializationGetRawSignature() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    byte[] rawSignatureBeforeSerialization = container.getSignature(0).getRawSignature();
    byte[] rawSignatureAfterSerialization = deserializedContainer.getSignature(0).getRawSignature();

    assertArrayEquals(rawSignatureBeforeSerialization, rawSignatureAfterSerialization);
  }

  @Test
  public void serializationGetTimeStampTokenCertificate() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    byte[] timeStampTokenCertificateBeforeSerialization = container.getSignature(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    byte[] timeStampTokenCertificateAfterSerialization = deserializedContainer.getSignature(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();

    assertArrayEquals(timeStampTokenCertificateBeforeSerialization, timeStampTokenCertificateAfterSerialization);
  }

  @Test
  public void serializationGetProfile() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    SignatureProfile signatureProfileBeforeSerialization = container.getSignature(0).getProfile();
    SignatureProfile signatureProfileAfterSerialization = deserializedContainer.getSignature(0).getProfile();

    assertEquals(signatureProfileBeforeSerialization, signatureProfileAfterSerialization);
  }

  @Test
  public void serializationGetDataFiles() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    int nrOfDataFilesBeforeSerialization = container.getDataFiles().size();
    int nrOfDataFilesAfterSerialization = deserializedContainer.getDataFiles().size();

    assertEquals(nrOfDataFilesBeforeSerialization, nrOfDataFilesAfterSerialization);
  }

  @Test
  public void serializationDataFileCheck() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    DataFile dataFileBeforeSerialization = container.getDataFile(0);
    DataFile dataFileAfterSerialization = deserializedContainer.getDataFile(0);

    assertEquals(dataFileBeforeSerialization.getFileSize(), dataFileAfterSerialization.getFileSize());
    assertArrayEquals(dataFileBeforeSerialization.getBytes(), dataFileAfterSerialization.getBytes());
    assertEquals(dataFileBeforeSerialization.getId(), dataFileAfterSerialization.getId());
    assertEquals(dataFileBeforeSerialization.getName(), dataFileAfterSerialization.getName());
    assertEquals(dataFileBeforeSerialization.getMediaType(), dataFileAfterSerialization.getMediaType());

    byte[] bytesBeforeSerialization = IOUtils.toByteArray(dataFileBeforeSerialization.getStream());
    byte[] bytesAfterSerialization = IOUtils.toByteArray(dataFileAfterSerialization.getStream());

    assertArrayEquals(bytesBeforeSerialization, bytesAfterSerialization);

    assertArrayEquals(dataFileAfterSerialization.calculateDigest(), dataFileBeforeSerialization.calculateDigest());
  }

  @Test(expected = Exception.class)
  public void testOCSPUnknown() {
    try {
      testSigningWithOCSPCheck("testFiles/20167000013.p12");
    } catch (Exception e) {
      assertTrue(e.getMessage().contains("UNKNOWN"));
      throw e;
    }
  }

  @Test(expected = Exception.class)
  public void testExpiredCertSign() {
    try {
      testSigningWithOCSPCheck("testFiles/expired_signer.p12");
    } catch (Exception e) {
      assertTrue(e.getMessage().contains("not in certificate validity range"));
      throw e;
    }
  }

  private void testSigningWithOCSPCheck(String unknownCert) {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSignerCert(unknownCert);
    SignedInfo signedInfo = container.prepareSigning(signerCert);
    byte[] signature = getExternalSignature(container, signerCert, signedInfo, SHA256, unknownCert);
    container.signRaw(signature);
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  @Ignore("Ignored because reference validation is turned off. Turn ON again when fixed")
  public void signatureFileContainsIncorrectFileName() {
    Container container = Container.open("testFiles/filename_mismatch_signature.asice");
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("The reference data object(s) not found!", validate.getErrors().get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void secondSignatureFileContainsIncorrectFileName() {
    Container container = Container.open("testFiles/filename_mismatch_second_signature.asice");
    ValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    assertEquals(3, errors.size());
    assertEquals("Manifest file has an entry for file test.txt with mimetype text/plain but the signature file for " +
        "signature S1 does not have an entry for this file", errors.get(0).toString());
    assertEquals("Container contains a file named test.txt which is not found in the signature file",
        errors.get(1).toString());
    assertEquals("The reference data object(s) is not intact!", errors.get(2).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void manifestFileContainsIncorrectFileName() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");
    Container container = Container.open("testFiles/filename_mismatch_manifest.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(2, validate.getErrors().size());
    assertEquals("Manifest file has an entry for file incorrect.txt with mimetype text/plain but the signature file " +
        "for signature S0 does not have an entry for this file", validate.getErrors().get(0).toString());
    assertEquals("The signature file for signature S0 has an entry for file RELEASE-NOTES.txt with mimetype " +
        "text/plain but the manifest file does not have an entry for this file",
        validate.getErrors().get(1).toString());
  }

  @Test
  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  public void revocationAndTimeStampDifferenceTooLarge() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");
    Container container = Container.open("testFiles/revocation_timestamp_delta_26h.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("The difference between the revocation time and the signature time stamp is too large",
        validate.getErrors().get(0).toString());
  }

  @Test
  public void revocationAndTimeStampDifferenceNotTooLarge() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint_SigningTimeCreationTimeDeltaIs27H.xml");
    Container container = Container.open("testFiles/revocation_timestamp_delta_26h.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(0, validate.getErrors().size());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void signatureFileAndManifestFileContainDifferentMimeTypeForFile() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");
    Container container = Container.open("testFiles/mimetype_mismatch.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("Manifest file has an entry for file RELEASE-NOTES.txt with mimetype application/pdf but the " +
        "signature file for signature S0 indicates the mimetype is text/plain", validate.getErrors().get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void dssReturnsEmptySignatureList() {
    Container container = Container.open("testFiles/filename_mismatch_signature.asice");
    ValidationResult validate = container.validate();

    // File name in signature does not match with manifest file info
    // Actual file inside container is same as in manifest (test.txt)
    assertEquals(3, validate.getErrors().size());

    // TODO: Ignored because reference validation is turned off. Turn ON again when fixed
    // assertEquals("The reference data object(s) not found!", validate.getErrors().get(0).toString());
  }

  @Test(expected = DigiDoc4JException.class)
  public void duplicateFileThrowsException() {
    Container container = Container.open("testFiles/22902_data_files_with_same_names.bdoc");
    container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void duplicateSignatureFileThrowsException() {
    Container container = Container.open("testFiles/22913_signatures_xml_double.bdoc");
    container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void missingManifestFile() {
    Container container = Container.open("testFiles/missing_manifest.asice");
    container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void missingMimeTypeFile() {
    Container.open("testFiles/missing_mimetype_file.asice");
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void containerHasFileWhichIsNotInManifestAndNotInSignatureFile() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");
    Container container = Container.open("testFiles/extra_file_in_container.asice", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Container contains a file named AdditionalFile.txt which is not found in the signature file",
        errors.get(0).getMessage());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  @Ignore("Ignored because reference validation is turned off. Turn ON again when fixed")
  public void containerMissesFileWhichIsInManifestAndSignatureFile() {
    Container container = Container.open("testFiles/zip_misses_file_which_is_in_manifest.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("The reference data object(s) not found!", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void containerMissingOCSPData() {
    Container container = Container.open("testFiles/TS-06_23634_TS_missing_OCSP_adjusted.asice");
    List<DigiDoc4JException> errors = container.validate().getErrors();

    assertEquals("ASiC_E_BASELINE_LT", container.getSignatureProfile());
    assertEquals(2, errors.size());
    assertTrue(errors.get(1).toString().contains("No revocation data for the certificate"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void corruptedOCSPDataThrowsException() {
    Container.open("testFiles/corrupted_ocsp_data.asice");
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void invalidNoncePolicyOid() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/23608_bdoc21-invalid-nonce-policy-oid.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Wrong policy identifier: urn:oid:1.3.6.1.4.1.10015.1000.3.4.3", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void noNoncePolicy() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/23608_bdoc21-no-nonce-policy.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Policy url is missing for identifier: urn:oid:1.3.6.1.4.1.10015.1000.3.2.1", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void badNonceContent() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/bdoc21-bad-nonce-content.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Nonce is invalid", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void noSignedPropRefTM() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/REF-03_bdoc21-TM-no-signedpropref.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Signed properties missing", errors.get(0).toString());
    assertEquals(1, container.getSignatures().get(0).validate().size());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void noSignedPropRefTS() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/REF-03_bdoc21-TS-no-signedpropref.asice", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Signed properties missing", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void multipleSignedProperties() {
    Container container = Container.open("testFiles/multiple_signed_properties.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(2, errors.size());
    assertEquals("The signature is not intact!", errors.get(0).toString());
    assertEquals("Multiple signed properties", errors.get(1).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void incorrectSignedPropertiesReference() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/signed_properties_reference_not_found.asice", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("The reference data object(s) not found!", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void nonceIncorrectContent() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/nonce-vale-sisu.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(3, errors.size());
    assertEquals("Nonce is invalid", errors.get(1).toString());
    assertEquals("Wrong policy identifier: urn:oid:1.3.6.1.4.1.10015.1000.2.10.10", errors.get(2).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void badNoncePolicyOidQualifier() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/SP-03_bdoc21-bad-nonce-policy-oidasuri.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Wrong policy identifier qualifier: OIDAsURI", errors.get(0).toString());
    assertEquals(1, container.getSignatures().get(0).validate().size());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void invalidNonce() {
    Container container = Container.open("testFiles/23200_weakdigest-wrong-nonce.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Nonce is invalid", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void noPolicyURI() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = Container.open("testFiles/SP-06_bdoc21-no-uri.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Policy url is missing for identifier: urn:oid:1.3.6.1.4.1.10015.1000.3.2.1", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void brokenTS() {
    Container container = Container.open("testFiles/TS_broken_TS.asice");
    ValidationResult result = container.validate();

    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals(MessageTag.ADEST_TSSIG_ANS.getMessage(), errors.get(0).toString());
  }

  @Test
  public void testBDocTM() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(LT_TM);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void containerWithBESProfileHasNoValidationErrors() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(B_BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    assertEquals("ASiC_E_BASELINE_B", container.getSignatureProfile());
    assertNull(container.getSignature(0).getOCSPCertificate());
    ValidationResult result = container.validate();
    assertEquals(0, result.getErrors().size());
  }

  @Test
  public void signWithECCCertificate() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setEncryptionAlgorithm(ECDSA);
    container.setSignatureParameters(signatureParameters);
    container.sign(new PKCS12Signer("testFiles/ec-digiid.p12", "inno".toCharArray()));

    assertTrue(container.validate().isValid());
  }

  @Test
  public void zipFileComment() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testZipFileComment.bdoc");

    ZipFile zipFile = new ZipFile("testZipFileComment.bdoc");
    String expectedComment = Helper.createUserAgent(container);
    assertEquals(expectedComment, zipFile.getComment());
  }
}
