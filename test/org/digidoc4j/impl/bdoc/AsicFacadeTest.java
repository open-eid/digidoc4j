/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.Signatures;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TSLHelper;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.testutils.TestSigningHelper;
import org.digidoc4j.utils.Helper;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.*;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipFile;

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.DigestAlgorithm.SHA224;
import static org.digidoc4j.SignatureProfile.*;
import static org.digidoc4j.DigestAlgorithm.SHA1;
import static org.digidoc4j.DigestAlgorithm.SHA256;
import static org.digidoc4j.testutils.TestDataBuilder.signContainer;
import static org.digidoc4j.utils.Helper.deserializer;
import static org.digidoc4j.utils.Helper.serialize;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class AsicFacadeTest extends DigiDoc4JTestHelper {

  private PKCS12SignatureToken PKCS12_SIGNER;

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

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
        if (fileName.endsWith("bdoc") && fileName.startsWith("test")) Files.deleteIfExists(item);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testSetDigestAlgorithmToSHA256() throws Exception {
    assertSettingDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256", SHA256);
  }

  @Test
  public void testSetDigestAlgorithmToSHA1() throws Exception {
    assertSettingDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1", SHA1);
  }

  @Test
  public void testSetDigestAlgorithmToSHA224() throws Exception {
    assertSettingDigestAlgorithm("http://www.w3.org/2001/04/xmldsig-more#sha224", SHA224);
  }

  private void assertSettingDigestAlgorithm(String expectedDigestAlgorithm, DigestAlgorithm actualDigestAlgorithm) throws IOException {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature)SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(actualDigestAlgorithm).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);
    assertEquals(expectedDigestAlgorithm, signature.getSignatureDigestAlgorithm().getXmlId());
  }

  @Test
  public void testDefaultDigestAlgorithm() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature)SignatureBuilder.
        aSignature(container).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureDigestAlgorithm().getXmlId());
  }

  @Test
  public void testOpenBDocDocument() throws Exception {
    Container container = open("testFiles/one_signature.bdoc");
    container.validate();
  }

  @Test
  public void testOpenBDocDocumentWithTwoSignatures() throws Exception {
    Container container = open("testFiles/two_signatures.bdoc");
    container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileWhenFileDoesNotExist() throws Exception {
    Container container = createContainerWithFile("notExisting.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileFromInputStreamWithByteArrayConversionFailure() throws Exception {
    Container container = create();
    container.addDataFile(new MockInputStream(), "test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddRawSignature() throws Exception {
    Container container = create();
    container.addRawSignature(new byte[]{});
  }

  @Test(expected = NotYetImplementedException.class)
  public void testAddRawSignatureFromInputStream() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    container.addRawSignature(new ByteArrayInputStream(Signatures.XADES_SIGNATURE.getBytes()));
    container.save("test_add_raw_signature.bdoc");

    Container openedContainer = open("test_add_raw_signature.bdoc");
    assertEquals(1, openedContainer.getSignatures().size());
  }

  @Test
  public void testAddUnknownFileTypeKeepsMimeType() {
    Container container = createContainerWithFile("testFiles/test.unknown_type", "text/test_type");
    signContainer(container);
    container.save("test_add_unknown_datafile_type.bdoc");

    Container open = ContainerOpener.open("test_add_unknown_datafile_type.bdoc");
    assertEquals("text/test_type", open.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void testSaveBDocDocumentWithTwoSignatures() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    signContainer(container);
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
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
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
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    signContainer(container);

    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12", container.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test
  public void notThrowingNPEWhenDOCXFileIsAddedToContainer() {
    Container container = createContainerWithFile("testFiles/word_file.docx", "text/xml");
    signContainer(container);
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testAddSignaturesToExistingDocument() throws Exception {
    Container container = open("testFiles/asics_testing_two_signatures.bdoc");
    signContainer(container);
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
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    container.removeSignature(0);
    container.save("testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());

    container = open("testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());
  }

    @Test
    public void testAddFilesWithSpecialCharactersIntoContainer() throws Exception {
      Container container = createContainerWithFile("testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt", "text/plain");
      container.addDataFile("testFiles/special-char-files/dds_колючей стерне.docx", "text/plain");
      signContainer(container);
      container.saveAsFile("testWithSpecialCharFiles.bdoc");

      assertEquals(0, container.validate().getContainerErrors().size());
    }

    @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() throws Exception {
    Container container = open("testFiles/asics_testing_two_signatures.bdoc");
    assertEquals(2, container.getSignatures().size());
    container.removeSignature(0);
    container.save("testRemoveSignature.bdoc");

    container = open("testRemoveSignature.bdoc");
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenThreeSignaturesExist() throws Exception {
    Container container = open("testFiles/asics_testing_two_signatures.bdoc");

    signContainer(container);
    container.save("testThreeSignatures.bdoc");
    container = open("testThreeSignatures.bdoc");
    assertEquals(3, container.getSignatures().size());

    container.removeSignature(1);

    container.save("testRemoveSignature.bdoc");

    container = open("testRemoveSignature.bdoc");
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void testSaveDocumentWithOneSignature() throws Exception {
    createSignedBDocDocument("testSaveBDocDocumentWithOneSignature.bdoc");
    assertTrue(Files.exists(Paths.get("testSaveBDocDocumentWithOneSignature.bdoc")));
  }

  @Test
  public void testVerifySignedDocument() throws Exception {
    Container container = createSignedBDocDocument("testSaveBDocDocumentWithOneSignature.bdoc");
    ValidationResult result = container.validate();
    assertFalse(result.hasErrors());
  }

  @Test
  public void testTestVerifyOnInvalidDocument() throws Exception {
    Container container = open("testFiles/invalid_container.bdoc");
    assertTrue(container.validate().hasErrors());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemoveDataFileAfterSigning() throws Exception {
    createSignedBDocDocument("testRemoveDataFile.bdoc");
    Container container = open("testRemoveDataFile.bdoc");
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testRemoveDataFile() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileAfterSigning() throws Exception {
    createSignedBDocDocument("testAddDataFile.bdoc");
    Container container = open("testAddDataFile.bdoc");
    container.addDataFile("testFiles/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNonExistingFile() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    container.removeDataFile("test1.txt");
  }


  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileSeveralTimes() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.txt", "text/plain");
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSamePreCreatedFileSeveralTimes() {
    Container container = create();
    DataFile dataFile = new DataFile("Hello world!".getBytes(), "test-file.txt", "text/plain");
    container.addDataFile(dataFile);
    container.addDataFile(dataFile);
  }

  @Test
  public void testAddingDifferentPreCreatedFiles() {
    Container container = create();
    container.addDataFile(new DataFile("Hello world!".getBytes(), "hello.txt", "text/plain"));
    container.addDataFile(new DataFile("Goodbye world!".getBytes(), "goodbye.txt", "text/plain"));
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileSeveralTimesViaInputStream() throws Exception {
    Container container = create();
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "testFiles/test.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "testFiles/test.txt", "text/plain");
  }

  @Test
  public void testAddDateFileViaInputStream() throws Exception {
    Container container = create();
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "testFiles/test.txt", "text/plain");
    signContainer(container);
    assertTrue(container.validate().isValid());
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileInDifferentContainerSeveralTimes() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/sub/test.txt", "text/plain");
    signContainer(container);
    container.save("testAddSameFile.bdoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingNotExistingFile() throws Exception {
    Container container = createContainerWithFile("notExistingFile.txt", "text/plain");
  }

  @Test
  public void testAddFileAsStream() throws Exception {
    Container container = create();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    signContainer(container);
    container.save("testAddFileAsStream.bdoc");

    Container containerToTest = open("testAddFileAsStream.bdoc");
    assertEquals("test1.txt", containerToTest.getDataFiles().get(0).getName());
  }

  @Test
  public void setsSignatureId() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");

    Signature signature1 = SignatureBuilder.
        aSignature(container).
        withSignatureId("SIGNATURE-1").
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature1);

    Signature signature2 = SignatureBuilder.
        aSignature(container).
        withSignatureId("SIGNATURE-2").
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature2);

    container.saveAsFile("setsSignatureId.bdoc");

    container = open("setsSignatureId.bdoc");
    assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    assertEquals("SIGNATURE-2", container.getSignature(1).getId());

    ZipFile zip = new ZipFile("setsSignatureId.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    signContainer(container);
    container.save("testSetsDefaultSignatureId.bdoc");

    container = open("testSetsDefaultSignatureId.bdoc");
    assertEquals("S0", container.getSignature(0).getId());
    assertEquals("S1", container.getSignature(1).getId());

    ZipFile zip = new ZipFile("testSetsDefaultSignatureId.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void getDataFileByIndex() {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);

    assertEquals("test.txt", container.getDataFile(0).getName());
  }

  @Test(expected = DigiDoc4JException.class)
  public void openNonExistingFileThrowsError() {
    open("non-existing.bdoc");
  }


  @Test(expected = DigiDoc4JException.class)
  public void openClosedStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("testFiles/test.txt"));
    stream.close();
    open(stream, false);
  }

  @Test
  public void testLargeFileSigning() throws Exception {
    BDocContainer container = (BDocContainer)create();
    container.getConfiguration().enableBigFilesSupport(10);
    String path = createLargeFile((container.getConfiguration().getMaxDataFileCachedInBytes()) + 100);
    container.addDataFile(path, "text/plain");
    signContainer(container);
  }


  @Test
  public void openLargeFileFromStream() throws FileNotFoundException {

    BDocContainer container = (BDocContainer)create();
    container.getConfiguration().enableBigFilesSupport(0);

    String path = createLargeFile((container.getConfiguration().getMaxDataFileCachedInBytes()) + 100);
    container.addDataFile(path, "text/plain");
    signContainer(container);
    container.save("test-large-file.bdoc");
    File file = new File("test-large-file.bdoc");
    FileInputStream fileInputStream = new FileInputStream(file);
    open(fileInputStream, true);

    IOUtils.closeQuietly(fileInputStream);

    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void openAddFileFromStream() throws IOException {
    BDocContainer container = (BDocContainer) create();
    container.getConfiguration().enableBigFilesSupport(0);

    String path = createLargeFile((container.getConfiguration().getMaxDataFileCachedInBytes()) + 100);
    try (FileInputStream stream = new FileInputStream(new File(path))) {
      container.addDataFile(stream, "fileName", "text/plain");
      signContainer(container);
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
    Container container = open("testGetDocumentType.bdoc");
    assertEquals(Container.DocumentType.BDOC, container.getDocumentType());
  }

  @Test
  public void testAddTwoFilesAsStream() throws Exception {
    Container container = create();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.addDataFile(stream, "test2.txt", "text/plain");
  }

  @Test
  public void testAddTwoFilesAsFileWithoutOCSP() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    signContainer(container, B_BES);
    container.save("testTwoFilesSigned.bdoc");

    container = open("testTwoFilesSigned.bdoc");
    assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void testGetFileNameAndID() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    signContainer(container);
    container.save("testTwoFilesSigned.bdoc");

    container = open("testTwoFilesSigned.bdoc");

    assertEquals("test.txt", container.getDataFile(0).getName());
    assertEquals("test.xml", container.getDataFile(1).getName());
    assertEquals("test.txt", container.getDataFile(0).getId());
    assertEquals("test.xml", container.getDataFile(1).getId());
  }

  @Test
  public void testAddTwoFilesAsFileWithOCSP() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    signContainer(container);
    container.save("testTwoFilesSigned.bdoc");

    container = open("testTwoFilesSigned.bdoc");
    assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void testValidateEmptyDocument() {
    Container container = create();
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
  }

  @Test
  public void testValidate() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    ValidationResult validationResult = container.validate();
    assertEquals(0, validationResult.getErrors().size());
  }

  @Test
  public void testLoadConfiguration() throws Exception {
    BDocContainer container = (BDocContainer) create();
    assertFalse(container.getConfiguration().isBigFilesSupportEnabled());
    container.getConfiguration().loadConfiguration("testFiles/digidoc_test_conf.yaml");
    assertTrue(container.getConfiguration().isBigFilesSupportEnabled());
    assertEquals(8192, container.getConfiguration().getMaxDataFileCachedInMB());
  }

  @Test
  public void saveToStream() throws Exception {
    Container container = create();
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "test_bytes.txt", "text/plain");
    signContainer(container);
    File expectedContainerAsFile = new File("testSaveToStreamTest.bdoc");
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    container.save(out);
    assertTrue(Files.exists(expectedContainerAsFile.toPath()));

    Container containerToTest = open(expectedContainerAsFile.getName());
    assertArrayEquals(new byte[]{0x42}, containerToTest.getDataFiles().get(0).getBytes());
  }

  @Test(expected = DigiDoc4JException.class)
  public void saveToStreamThrowsException() throws IOException {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    File expectedContainerAsFile = new File("testSaveToStreamTest.bdoc");
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    out.close();
    container.save(out);
  }

  @Test
  @Ignore("This feature should not be implemented. It's a bug not a feature")
  public void configurationImmutabilityWhenLoadingFromFile() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    container.save("test_immutable.bdoc");

    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    String tspSource = configuration.getTspSource();

    container = open("test_immutable.bdoc", configuration);
    configuration.setTspSource("changed_tsp_source");

    assertEquals(tspSource, ((BDocContainer)container).getConfiguration().getTspSource());
  }

  @Test
  //@Ignore("RIA VPN")
  public void TSLIsLoadedAfterSettingNewTSLLocation() {
    Configuration configuration = new Configuration();
    configuration.setTslLocation("file:test-tsl/trusted-test-mp.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        build();
    container.getConfiguration().getTSL();
    assertEquals(5, container.getConfiguration().getTSL().getCertificates().size());

    configuration.setTslLocation("http://10.0.25.57/tsl/trusted-test-mp.xml");
    container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        build();
    assertNotEquals(5, container.getConfiguration().getTSL().getCertificates().size());
  }

  @Test (expected = DigiDoc4JException.class)
  public void TSLFileNotFoundThrowsException() {
    Configuration configuration = new Configuration();
    configuration.setTslLocation("file:test-tsl/NotExisting.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        build();
    container.getConfiguration().getTSL();
  }

  @Test (expected = DigiDoc4JException.class)
  public void TSLConnectionFailureThrowsException() {
    Configuration configuration = new Configuration();
    configuration.setTslLocation("http://127.0.0.1/tsl/incorrect.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        build();
    container.getConfiguration().getTSL();
  }

  @Test
  public void extendFromB_BESToTS() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, B_BES);
    container.save("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = open("testExtendTo.bdoc");
    container.extendTo(SignatureProfile.LT);
    container.save("testExtendToContainsIt.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void extendFromB_BESToLTA() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, B_BES);
    container.save("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = open("testExtendTo.bdoc");
    container.extendTo(SignatureProfile.LTA);
    container.save("testExtendToContainsIt.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test (expected = DigiDoc4JException.class)
  public void extendFromB_BESToLT_TMThrowsException() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, B_BES);
    container.extendTo(SignatureProfile.LT_TM);
  }

  @Test (expected = DigiDoc4JException.class)
  public void extendFromLTToLT_TMThrowsException() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, LT);
    container.extendTo(SignatureProfile.LT_TM);
  }

  @Test (expected = DigiDoc4JException.class)
  public void extendFromLTAToLT_TMThrowsException() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, LTA);
    container.extendTo(SignatureProfile.LT_TM);
  }

  @Test
  public void containerIsLT() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, LT);
    container.saveAsFile("testLT.bdoc");
    container = open("testLT.bdoc");
    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void verifySignatureProfileIsTS() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, LT);
    container.saveAsFile("testAddConfirmation.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extendToWhenConfirmationAlreadyExists() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, B_BES);
    container.saveAsFile("testExtendTo.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());

    container = open("testExtendTo.bdoc");
    container.extendTo(LT);
    container.extendTo(LT);
  }

  @Test(expected = DigiDoc4JException.class)
  public void signWithoutDataFile() throws Exception {
    Container container = create();
    signContainer(container);
  }

  @Test
  public void extendToWithMultipleSignatures() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container, B_BES);
    signContainer(container, B_BES);
    container.saveAsFile("testExtendTo.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertNull(container.getSignature(0).getOCSPCertificate());
    assertNull(container.getSignature(1).getOCSPCertificate());

    container = open("testExtendTo.bdoc");
    container.extendTo(LT);
    container.save("testExtendToContainsIt.bdoc");

    container = open("testExtendToContainsIt.bdoc");
    assertEquals(2, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
    assertNotNull(container.getSignature(1).getOCSPCertificate());
  }

  @Test
  public void extendToWithMultipleSignaturesAndMultipleFiles() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.xml", "text/xml");
    signContainer(container, B_BES);
    signContainer(container, B_BES);
    container.saveAsFile("testAddConfirmation.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertEquals(2, container.getDataFiles().size());
    assertNull(container.getSignature(0).getOCSPCertificate());
    assertNull(container.getSignature(1).getOCSPCertificate());

    container = open("testAddConfirmation.bdoc");
    container.extendTo(LT);
    container.save("testAddConfirmationContainsIt.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertEquals(2, container.getDataFiles().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
    assertNotNull(container.getSignature(1).getOCSPCertificate());
  }

  @Test(expected = UnsupportedFormatException.class)
  public void notBDocThrowsException() {
    open("testFiles/notABDoc.bdoc");
  }

  @Test(expected = UnsupportedFormatException.class)
  public void incorrectMimetypeThrowsException() {
    open("testFiles/incorrectMimetype.bdoc");
  }

  @Test
  public void nonStandardMimeType() {
    Container container = ContainerBuilder.aContainer(BDOC_CONTAINER_TYPE).build();
    container.addDataFile("testFiles/test.txt", "text/newtype");
    signContainer(container);
    container.save("testNonStandardMimeType.bdoc");
    container = ContainerOpener.open("testNonStandardMimeType.bdoc");
    ValidationResult result = container.validate();
    assertEquals(0, result.getErrors().size());
    assertEquals("text/newtype", container.getDataFile(0).getMediaType());
  }

  /*@Test(expected = DigiDoc4JException.class)
  public void signingThrowsNormalDSSException() {
    MockAsicFacade container = new MockAsicFacade("Normal DSS Exception");
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signingThrowsOCSPException() {
    MockAsicFacade container = new MockAsicFacade("OCSP request failed");
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
  }*/

  @Test
  public void getVersion() {
    Container container = create();
    assertNull(container.getVersion());
  }

  @Test
  public void testContainerExtensionFromLTtoLTA() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);

    container.extendTo(LTA);
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void twoStepSigning() throws IOException {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSignerCert();
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert).
        buildDataToSign();
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile("test.bdoc");

    container = ContainerOpener.open("test.bdoc");

    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());

    assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", resultSignature.getSignatureMethod());
    assertNull(resultSignature.getSignerRoles());
    assertNull(resultSignature.getCity());
    assertTrue(StringUtils.isNotBlank(resultSignature.getId()));

    assertNotNull(resultSignature.getOCSPCertificate());
    assertNotNull(resultSignature.getSigningCertificate());
    assertNotNull(resultSignature.getAdESSignature().length);
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
    Container container = ContainerBuilder.aContainer(BDOC_CONTAINER_TYPE).build();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSignerCert();
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).
        withSigningCertificate(signerCert).
        withSignatureId("S99").
        withRoles("manager", "employee").
        withCity("city").
        withStateOrProvince("state").
        withPostalCode("postalCode").
        withCountry("country").
        buildDataToSign();
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile("test.bdoc");

    container = ContainerOpener.open("test.bdoc");
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
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert).
        buildDataToSign();

    serialize(container, "container.bin");
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());

    container = deserializer("container.bin");
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile("test.bdoc");

    container = ContainerOpener.open("test.bdoc");

    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());

    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testContainerCreationAsTSA() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container, LTA);

    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extensionNotPossibleWhenSignatureLevelIsSame() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container, LTA);
    container.extendTo(LTA);
  }

  private Container createSignedBDocDocument(String fileName) {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
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
    signContainer(container);

    serialize(container, "container.bin");

    Container deserializedContainer = deserializer("container.bin");

    assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializationVerifySpecifiedSignatureParameters() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).
        withSignatureToken(PKCS12_SIGNER).
        withSignatureId("S99").
        withRoles("manager", "employee").
        withCity("city").
        withStateOrProvince("state").
        withPostalCode("postalCode").
        withCountry("country").
        invokeSigning();
    container.addSignature(signature);

    serialize(container, "container.bin");

    Container deserializedContainer = deserializer("container.bin");

    Signature deserializedSignature = deserializedContainer.getSignature(0);
    assertEquals("postalCode", deserializedSignature.getPostalCode());
    assertEquals("city", deserializedSignature.getCity());
    assertEquals("state", deserializedSignature.getStateOrProvince());
    assertEquals("country", deserializedSignature.getCountryName());
    assertEquals("employee", deserializedSignature.getSignerRoles().get(1));
    assertEquals("S99", deserializedSignature.getId());
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", deserializedSignature.getSignatureMethod());
  }

  @Test
  public void serializationVerifyDefaultSignatureParameters() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    Signature signature = deserializedContainer.getSignature(0);

    assertNull(signature.getCity());
    assertNull(signature.getSignerRoles());
    assertEquals("S0", signature.getId());
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
  }

  @Test
  public void serializationGetDocumentType() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    assertEquals(container.getDocumentType(), deserializedContainer.getDocumentType());
  }

  @Test
  public void serializationGetOCSPCertificate() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
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
    signContainer(container);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    Date signingTimeBeforeSerialization = container.getSignature(0).getClaimedSigningTime();
    Date signingTimeAfterSerialization = deserializedContainer.getSignature(0).getClaimedSigningTime();

    assertEquals(signingTimeBeforeSerialization, signingTimeAfterSerialization);
  }

  @Test(expected = NotYetImplementedException.class)
  public void serializationGetPolicy() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
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
    signContainer(container);
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
    signContainer(container);
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
    signContainer(container);
    serialize(container, "container.bin");
    Container deserializedContainer = deserializer("container.bin");

    byte[] rawSignatureBeforeSerialization = container.getSignature(0).getAdESSignature();
    byte[] rawSignatureAfterSerialization = deserializedContainer.getSignature(0).getAdESSignature();

    assertArrayEquals(rawSignatureBeforeSerialization, rawSignatureAfterSerialization);
  }

  @Test
  public void serializationGetTimeStampTokenCertificate() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
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
    signContainer(container);
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
    signContainer(container);
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
    signContainer(container);
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

  @Ignore("Unable to test if OCSP responds with unknown, because the signing certificate is expired")
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
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert).
        buildDataToSign();
    byte[] signature = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    dataToSign.finalize(signature);
  }

  @Test
  public void signatureFileContainsIncorrectFileName() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    Container container = ContainerOpener.open("testFiles/filename_mismatch_signature.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("The reference data object(s) not found!", validate.getErrors().get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void secondSignatureFileContainsIncorrectFileName() throws IOException, CertificateException {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TSLHelper.addSkTsaCertificateToTsl(configuration);
    Container container = ContainerOpener.open("testFiles/filename_mismatch_second_signature.asice", configuration);
    ValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    assertEquals(3, errors.size());
    assertEquals("The reference data object(s) is not intact!", errors.get(0).toString());
    assertEquals("Manifest file has an entry for file test.txt with mimetype text/plain but the signature file for " +
        "signature S1 does not have an entry for this file", errors.get(1).toString());
    assertEquals("Container contains a file named test.txt which is not found in the signature file",
        errors.get(2).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void manifestFileContainsIncorrectFileName() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");
    Container container = ContainerOpener.open("testFiles/filename_mismatch_manifest.asice", configuration);
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
    Container container = ContainerOpener.open("testFiles/revocation_timestamp_delta_26h.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("The difference between the revocation time and the signature time stamp is too large",
        validate.getErrors().get(0).toString());
  }

  @Test
  public void revocationAndTimeStampDifferenceNotTooLarge() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    int delta27Hours = 27 * 60;
    configuration.setRevocationAndTimestampDeltaInMinutes(delta27Hours);
    Container container = ContainerOpener.open("testFiles/revocation_timestamp_delta_26h.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(0, validate.getErrors().size());
  }

  @Test
  public void signatureFileAndManifestFileContainDifferentMimeTypeForFile() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");
    Container container = ContainerOpener.open("testFiles/mimetype_mismatch.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("Manifest file has an entry for file RELEASE-NOTES.txt with mimetype application/pdf but the " +
        "signature file for signature S0 indicates the mimetype is text/plain", validate.getErrors().get(0).toString());
  }

  @Test
  public void dssReturnsEmptySignatureList() {
    Container container = ContainerOpener.open("testFiles/filename_mismatch_signature.asice");
    ValidationResult validate = container.validate();

    // File name in signature does not match with manifest file info
    // Actual file inside container is same as in manifest (test.txt)
    assertEquals(1, validate.getErrors().size());
    assertEquals("The reference data object(s) not found!", validate.getErrors().get(0).toString());
  }

  @Test(expected = DuplicateDataFileException.class)
  public void duplicateFileThrowsException() {
    Container container = ContainerOpener.open("testFiles/22902_data_files_with_same_names.bdoc");
    container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void duplicateSignatureFileThrowsException() {
    Container container = ContainerOpener.open("testFiles/22913_signatures_xml_double.bdoc");
    container.validate();
  }

  @Test
  public void missingManifestFile() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    Container container = ContainerOpener.open("testFiles/missing_manifest.asice", configuration);
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("Unsupported format: Container does not contain a manifest file", result.getErrors().get(0).getMessage());
  }

  @Test(expected = DigiDoc4JException.class)
  public void missingMimeTypeFile() {
    ContainerOpener.open("testFiles/missing_mimetype_file.asice");
  }

  @Test
  public void containerHasFileWhichIsNotInManifestAndNotInSignatureFile() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");
    Container container = ContainerOpener.open("testFiles/extra_file_in_container.asice", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Container contains a file named AdditionalFile.txt which is not found in the signature file",
        errors.get(0).getMessage());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void containerMissesFileWhichIsInManifestAndSignatureFile() {
    Container container = ContainerOpener.open("testFiles/zip_misses_file_which_is_in_manifest.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("The reference data object(s) is not intact!", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void containerMissingOCSPData() {
    Container container = ContainerOpener.open("testFiles/TS-06_23634_TS_missing_OCSP_adjusted.asice");
    List<DigiDoc4JException> errors = container.validate().getErrors();

    assertEquals(LT, container.getSignatures().get(0).getProfile());
    assertEquals(2, errors.size());
    assertTrue(errors.get(0).toString().contains("No revocation data for the certificate"));
    assertEquals("Manifest file has an entry for file test.txt with mimetype text/plain but the signature file for signature S0 indicates the mimetype is application/octet-stream", errors.get(1).toString());
  }

  @Ignore("This signature has two OCSP responses: one correct and one is technically corrupted. Opening a container should not throw an exception")
  @Test(expected = DigiDoc4JException.class)
  public void corruptedOCSPDataThrowsException() {
    ContainerOpener.open("testFiles/corrupted_ocsp_data.asice");
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void invalidNoncePolicyOid() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = ContainerOpener.open("testFiles/23608_bdoc21-invalid-nonce-policy-oid.bdoc", configuration);
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

    Container container = ContainerOpener.open("testFiles/23608_bdoc21-no-nonce-policy.bdoc", configuration);
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

    Container container = ContainerOpener.open("testFiles/bdoc21-bad-nonce-content.bdoc", configuration);
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

    Container container = ContainerOpener.open("testFiles/REF-03_bdoc21-TM-no-signedpropref.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(2, errors.size());
    assertContainsError("Signed properties missing", errors);
    assertContainsError("The reference data object(s) not found!", errors);
    assertEquals(2, container.getSignatures().get(0).validate().size());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void noSignedPropRefTS() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = ContainerOpener.open("testFiles/REF-03_bdoc21-TS-no-signedpropref.asice", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(2, errors.size());
    assertContainsError("Signed properties missing", errors);
    assertContainsError("The reference data object(s) not found!", errors);
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void multipleSignedProperties() {
    Container container = ContainerOpener.open("testFiles/multiple_signed_properties.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(2, errors.size());
    assertEquals("Multiple signed properties", errors.get(0).toString());
    assertEquals("The signature is not intact!", errors.get(1).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void incorrectSignedPropertiesReference() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = ContainerOpener.open("testFiles/signed_properties_reference_not_found.asice", configuration);
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

    Container container = ContainerOpener.open("testFiles/nonce-vale-sisu.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(4, errors.size());
    assertEquals("Wrong policy identifier: urn:oid:1.3.6.1.4.1.10015.1000.2.10.10", errors.get(0).toString());
    assertEquals("The reference data object(s) is not intact!", errors.get(1).toString());
    assertEquals("Nonce is invalid", errors.get(2).toString());
    assertEquals("The signature file for signature S0 has an entry for file META-INF/manifest.xml with mimetype application/xml but the manifest file does not have an entry for this file", errors.get(3).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void badNoncePolicyOidQualifier() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setValidationPolicy("conf/test_constraint.xml");

    Container container = ContainerOpener.open("testFiles/SP-03_bdoc21-bad-nonce-policy-oidasuri.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Wrong policy identifier qualifier: OIDAsURI", errors.get(0).toString());
    assertEquals(1, container.getSignatures().get(0).validate().size());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void invalidNonce() {
    Container container = ContainerOpener.open("testFiles/23200_weakdigest-wrong-nonce.asice");
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

    Container container = ContainerOpener.open("testFiles/SP-06_bdoc21-no-uri.bdoc", configuration);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Policy url is missing for identifier: urn:oid:1.3.6.1.4.1.10015.1000.3.2.1", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void brokenTS() {
    Container container = ContainerOpener.open("testFiles/TS_broken_TS.asice");
    ValidationResult result = container.validate();

    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(2, errors.size());
    assertEquals(InvalidTimestampException.MESSAGE, errors.get(0).toString());
    assertEquals(TimestampAfterOCSPResponseTimeException.MESSAGE, errors.get(1).toString());
  }

  @Test
  public void testBDocTM() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container, LT_TM);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void testBDocTS() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container, LT);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void containerWithBESProfileHasNoValidationErrors() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container, B_BES);

    assertEquals(B_BES, container.getSignatures().get(0).getProfile());
    assertNull(container.getSignature(0).getOCSPCertificate());
    ValidationResult result = container.validate();
    assertEquals(0, result.getErrors().size());
  }

  @Test
  public void signWithECCCertificate() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(new PKCS12SignatureToken("testFiles/ec-digiid.p12", "inno".toCharArray())).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).
        invokeSigning();
    container.addSignature(signature);
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void zipFileComment() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    container.save("testZipFileComment.bdoc");

    String expectedComment = Helper.createBDocUserAgent();
    ZipFile zipFile = new ZipFile("testZipFileComment.bdoc");
    assertEquals(expectedComment, zipFile.getEntry("mimetype").getComment());
    assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
    assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
    assertEquals(expectedComment, zipFile.getEntry("META-INF/signatures0.xml").getComment());
    assertEquals(expectedComment, zipFile.getEntry("test.txt").getComment());
  }

  @Test
  public void signingMoreThanTwoFiles() throws Exception {
    Container container = createContainerWithFile("testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt", "text/plain");
      container.addDataFile("testFiles/special-char-files/dds_колючей стерне.docx", "text/plain");
      container.addDataFile("testFiles/special-char-files/dds_pakitud.zip", "text/plain");
      container.addDataFile("testFiles/special-char-files/dds_SK.jpg", "text/plain");
      container.addDataFile("testFiles/special-char-files/dds_acrobat.pdf", "text/plain");

      signContainer(container);

      BDocSignature signature = (BDocSignature)container.getSignature(0);
      assertSignatureContains(signature, "dds_dds_JÜRIÖÖ € žŠ päev.txt");
      assertSignatureContains(signature, "dds_колючей стерне.docx");
      assertSignatureContains(signature, "dds_pakitud.zip");
      assertSignatureContains(signature, "dds_SK.jpg");
      assertSignatureContains(signature, "dds_acrobat.pdf");
  }

  @Test
  public void signatureFileNamesShouldBeInSequence() throws Exception {
    Container container = createContainerWithFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    signContainer(container);
    signContainer(container);
    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    ZipFile zip = new ZipFile(containerPath);
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
  }

  @Test
  public void whenSigningExistingContainer_withTwoSignatures_shouldCreateSignatureFileName_signatures2() throws Exception {
    ZipFile zip = new ZipFile("testFiles/asics_testing_two_signatures.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = open("testFiles/asics_testing_two_signatures.bdoc");
    signContainer(container);
    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    zip = new ZipFile(containerPath);
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
  }

  @Test
  public void whenSigningExistingContainer_with_signatures1_xml_shouldCreateSignatureFileName_signatures2() throws Exception {
    ZipFile zip = new ZipFile("testFiles/DigiDocService_spec_est.pdf-TM-j.bdoc");
    assertNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = open("testFiles/DigiDocService_spec_est.pdf-TM-j.bdoc");
    signContainer(container);
    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    zip = new ZipFile(containerPath);
    assertNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
  }

  @Test(expected = DuplicateDataFileException.class)
  public void whenOpeningContainer_withTwoDataFilesWithSameName_andWithSingleReferenceInManifest_shouldThrowException() {
    Container container = ContainerBuilder.aContainer()
        .fromExistingFile("testFiles/KS-19_IB-3721_bdoc21-TM-2fil-samename-1sig3.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST))
        .build();
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signingContainer_withFailedOcspResponse_shouldThrowException() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setSignOCSPRequests(true);
    configuration.setOCSPAccessCertificateFileName("testFiles/signout.p12");
    configuration.setOCSPAccessCertificatePassword("test".toCharArray());
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        withDataFile("testFiles/test.txt", "text/plain").
        build();

    signContainer(container, LT_TM);
  }

  /**
   * This is necessary for jDigidoc compatibility. This requirement not in BDoc specification
   */
  @Test
  public void bdocTM_OcspResponderCert_shouldContainResponderCertIdAttribute() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    BDocSignature signature = (BDocSignature) signContainer(container, LT_TM);
    XAdESSignature xAdESSignature = signature.getOrigin();
    assertTrue(signatureContainsOcspResponderCertificate(xAdESSignature));
  }

  @Test
  public void savingContainerWithoutSignatures_shouldNotThrowException() throws Exception {
    Container container = create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    assertTrue(container.getSignatures().isEmpty());
    assertEquals(1, container.getDataFiles().size());
    assertTrue(container.validate().isValid());
    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    Container savedContainer = open(containerPath);
    assertTrue(savedContainer.getSignatures().isEmpty());
    assertEquals(1, container.getDataFiles().size());
    byte[] expectedDataFileBytes = FileUtils.readFileToByteArray(new File("testFiles/test.txt"));
    byte[] actualDataFileBytes = savedContainer.getDataFiles().get(0).getBytes();
    Assert.assertArrayEquals(expectedDataFileBytes, actualDataFileBytes);
  }

  private void assertSignatureContains(BDocSignature signature, String name) {
      assertNotNull(findSignedFile(signature, name));
  }

  private DSSDocument findSignedFile(BDocSignature signature, String name) {
      List<DSSDocument> signedFiles = signature.getOrigin().getDetachedContents();
      for (DSSDocument signedFile : signedFiles) {
          if(name.equals(signedFile.getName())) {
              return signedFile;
          }
      }
      return null;
  }

  private void assertContainsError(String errorMsg, List<DigiDoc4JException> errors) {
    for (DigiDoc4JException e : errors) {
      if (StringUtils.equalsIgnoreCase(errorMsg, e.toString())) {
        return;
      }
    }
    assertFalse("Expected '" + errorMsg + "' was not found", true);
  }

  private Container open(String path) {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        fromExistingFile(path).
        build();
    return container;
  }

  private Container open(String path, Configuration configuration) {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile(path).
        build();
    return container;
  }

  private Container open(InputStream fileInputStream, boolean actAsBigFilesSupportEnabled) {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        fromStream(fileInputStream).
        build();
    return container;
  }

  private Container create() {
    return ContainerBuilder.aContainer(BDOC_CONTAINER_TYPE).build();
  }

  private Container createContainerWithFile(String path, String mimeType) {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withDataFile(path, mimeType).
        build();
    return container;
  }
  private boolean signatureContainsOcspResponderCertificate(XAdESSignature xAdESSignature) {
    XPathQueryHolder xPathQueryHolder = xAdESSignature.getXPathQueryHolder();
    String xPath = xPathQueryHolder.XPATH_CERTIFICATE_VALUES;
    Element certificateValues = DSSXMLUtils.getElement(xAdESSignature.getSignatureElement(), xPath);
    return certificateValuesContainResponderCertId(certificateValues);
  }

  private boolean certificateValuesContainResponderCertId(Element certificateValues) {
    NodeList certificates = certificateValues.getChildNodes();
    for(int i = 0;i < certificates.getLength(); i++) {
      Node cert = certificates.item(i);
      Node certId = cert.getAttributes().getNamedItem("Id");
      if(certId != null) {
        String idValue = certId.getNodeValue();
        if(StringUtils.endsWithIgnoreCase(idValue, "RESPONDER_CERT")) {
          return true;
        }
      }
    }
    return false;
  }
}
