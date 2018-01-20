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

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.digidoc4j.Constant.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.DigestAlgorithm.SHA1;
import static org.digidoc4j.DigestAlgorithm.SHA224;
import static org.digidoc4j.DigestAlgorithm.SHA256;
import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.SignatureProfile.LT_TM;
import static org.digidoc4j.testutils.TestDataBuilder.PKCS12_SIGNER;
import static org.digidoc4j.testutils.TestDataBuilder.createEmptyBDocContainer;
import static org.digidoc4j.testutils.TestDataBuilder.signContainer;
import static org.digidoc4j.testutils.TestSigningHelper.getSigningCert;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.testutils.TestSigningHelper;
import org.digidoc4j.utils.Helper;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class BDocContainerTest extends DigiDoc4JTestHelper {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @After
  public void cleanUp() {
    testFolder.delete();
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
    Container container = open("src/test/resources/testFiles/valid-containers/one_signature.bdoc");
    container.validate();
  }

  @Test
  public void testOpenBDocDocumentWithTwoSignatures() throws Exception {
    Container container = open("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc");
    container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileWhenFileDoesNotExist() throws Exception {
    Container container = createContainerWithFile("notExisting.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileFromInputStreamWithByteArrayConversionFailure() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile(new MockInputStream(), "test.txt", "text/plain");
  }

  @Test(expected = InvalidSignatureException.class)
  public void testAddRawSignature() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addRawSignature(new byte[]{});
  }

  @Test
  public void testAddUnknownFileTypeKeepsMimeType() {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.unknown_type", "text/test_type");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/test_add_unknown_datafile_type.bdoc");

    Container open = ContainerOpener.open("src/test/resources/testFiles/tmp/test_add_unknown_datafile_type.bdoc");
    assertEquals("text/test_type", open.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void testSaveBDocDocumentWithTwoSignatures() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testTwoSignatures.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(1).getSigningCertificate().getSerial());

    Container openedContainer = open("src/test/resources/testFiles/tmp/testTwoSignatures.bdoc");

    assertEquals(2, openedContainer.getSignatures().size());
    assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        openedContainer.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        openedContainer.getSignatures().get(1).getSigningCertificate().getSerial());
  }

  @Test
  public void saveContainerWithoutSignatures() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    String path = testFolder.newFile("container.bdoc").getPath();
    container.saveAsFile(path);
    container = open(path);
    assertEquals(1, container.getDataFiles().size());
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
  }

  @Test
  public void openContainer_withoutSignatures_andAddMoreDataFiles() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    assertEquals(1, container.getDataFiles().size());
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    container.addDataFile("src/test/resources/testFiles/helper-files/word_file.docx", "application/octet-stream");
    assertEquals(3, container.getDataFiles().size());
    String path = testFolder.newFile("container.bdoc").getPath();
    container.saveAsFile(path);
    container = open(path);
    assertEquals(3, container.getDataFiles().size());
  }

  @Test
  public void openContainerFromStream_withoutSignatures_andAddMoreDataFiles() throws Exception {
    FileInputStream stream = new FileInputStream("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    Container container = open(stream);
    assertEquals(1, container.getDataFiles().size());
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    container.addDataFile("src/test/resources/testFiles/helper-files/word_file.docx", "application/octet-stream");
    assertEquals(3, container.getDataFiles().size());
    String path = testFolder.newFile("container.bdoc").getPath();
    container.saveAsFile(path);
    stream = new FileInputStream(path);
    container = open(stream);
    assertEquals(3, container.getDataFiles().size());
  }

  @Test
  public void openContainerWithoutSignatures_addDataFileAndSignContainer() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    assertEquals(1, container.getDataFiles().size());
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    signContainer(container);
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.validate().isValid());
    String path = testFolder.newFile("container.bdoc").getPath();
    container.saveAsFile(path);
    container = open(path);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void testGetDefaultSignatureParameters() {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/test.bdoc");

    container = open("src/test/resources/testFiles/tmp/test.bdoc");
    Signature signature = container.getSignature(0);
    assertEquals("", signature.getPostalCode());
    assertEquals("", signature.getCity());
    assertEquals("", signature.getStateOrProvince());
    assertEquals("", signature.getCountryName());
    assertThat(signature.getSignerRoles(), is(empty()));
  }

  @Test
  public void getSignatureByIndex() {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    signContainer(container);

    assertEquals("530be41bbc597c44570e2b7c13bcfa0c", container.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test
  public void notThrowingNPEWhenDOCXFileIsAddedToContainer() {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/word_file.docx", "text/xml");
    signContainer(container);
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void signPdfDataFile() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf", "application/pdf");
    signContainer(container);
    assertEquals(1, container.getDataFiles().size());
    assertEquals(1, container.getSignatures().size());
    String containerPath = testFolder.newFile("container.bdoc").getPath();
    container.saveAsFile(containerPath);
    container = open(containerPath);
    assertEquals(1, container.getDataFiles().size());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void testAddSignaturesToExistingDocument() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testAddMultipleSignatures.bdoc");

    assertEquals(3, container.getSignatures().size());
    assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(2).getSigningCertificate().getSerial());

    Container openedContainer = open("src/test/resources/testFiles/tmp/testAddMultipleSignatures.bdoc");

    assertEquals(3, openedContainer.getSignatures().size());
    assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        openedContainer.getSignatures().get(2).getSigningCertificate().getSerial());

    ValidationResult validationResult = openedContainer.validate();
    assertEquals(0, validationResult.getErrors().size());
  }

  @Test
  public void testRemoveSignatureWhenOneSignatureExists() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    container.removeSignature(0);
    container.save("src/test/resources/testFiles/tmp/testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());

    container = open("src/test/resources/testFiles/tmp/testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());
  }

    @Test
    public void testAddFilesWithSpecialCharactersIntoContainer() throws Exception {
      Container container = createContainerWithFile("src/test/resources/testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt", "text/plain");
      //container.addDataFile("src/test/resources/testFiles/special-char-files/dds_колючей стерне.docx", "text/plain");
      signContainer(container);
      container.saveAsFile("src/test/resources/testFiles/tmp/testWithSpecialCharFiles.bdoc");

      assertEquals(0, container.validate().getContainerErrors().size());
    }

    @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    assertEquals(2, container.getSignatures().size());
    container.removeSignature(0);
    container.save("src/test/resources/testFiles/tmp/testRemoveSignature.bdoc");

    container = open("src/test/resources/testFiles/tmp/testRemoveSignature.bdoc");
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenThreeSignaturesExist() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");

    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testThreeSignatures.bdoc");
    container = open("src/test/resources/testFiles/tmp/testThreeSignatures.bdoc");
    assertEquals(3, container.getSignatures().size());

    container.removeSignature(1);

    container.save("src/test/resources/testFiles/tmp/testRemoveSignature.bdoc");

    container = open("src/test/resources/testFiles/tmp/testRemoveSignature.bdoc");
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void removeNewlyAddedSignatureFromExistingContainer() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    assertEquals(2, container.getSignatures().size());
    signContainer(container);
    assertEquals(3, container.getSignatures().size());
    container.removeSignature(container.getSignatures().get(0));
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void removeSignatureFromExistingContainer() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    assertEquals(2, container.getSignatures().size());
    container.removeSignature(container.getSignatures().get(0));
    assertEquals(1, container.getSignatures().size());
    String path = testFolder.newFile("container.bdoc").getPath();
    container.saveAsFile(path);
    container = open(path);
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testSaveDocumentWithOneSignature() throws Exception {
    createSignedBDocDocument("src/test/resources/testFiles/tmp/testSaveBDocDocumentWithOneSignature.bdoc");
    assertTrue(Files.exists(Paths.get("src/test/resources/testFiles/tmp/testSaveBDocDocumentWithOneSignature.bdoc")));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemoveDataFileAfterSigning() throws Exception {
    createSignedBDocDocument("src/test/resources/testFiles/tmp/testRemoveDataFile.bdoc");
    Container container = open("src/test/resources/testFiles/tmp/testRemoveDataFile.bdoc");
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testRemoveDataFile() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileAfterSigning() throws Exception {
    createSignedBDocDocument("src/test/resources/testFiles/tmp/testAddDataFile.bdoc");
    Container container = open("src/test/resources/testFiles/tmp/testAddDataFile.bdoc");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNonExistingFile() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.removeDataFile("test1.txt");
  }


  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileSeveralTimes() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSamePreCreatedFileSeveralTimes() {
    Container container = createEmptyBDocContainer();
    DataFile dataFile = new DataFile("Hello world!".getBytes(), "test-file.txt", "text/plain");
    container.addDataFile(dataFile);
    container.addDataFile(dataFile);
  }

  @Test
  public void testAddingDifferentPreCreatedFiles() {
    Container container = createEmptyBDocContainer();
    container.addDataFile(new DataFile("Hello world!".getBytes(), "hello.txt", "text/plain"));
    container.addDataFile(new DataFile("Goodbye world!".getBytes(), "goodbye.txt", "text/plain"));
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileSeveralTimesViaInputStream() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test
  public void testAddDateFileViaInputStream() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    assertTrue(container.validate().isValid());
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileInDifferentContainerSeveralTimes() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testAddSameFile.bdoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingNotExistingFile() throws Exception {
    Container container = createContainerWithFile("notExistingFile.txt", "text/plain");
  }

  @Test
  public void testAddFileAsStream() throws Exception {
    Container container = createEmptyBDocContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testAddFileAsStream.bdoc");

    Container containerToTest = open("src/test/resources/testFiles/tmp/testAddFileAsStream.bdoc");
    assertEquals("test1.txt", containerToTest.getDataFiles().get(0).getName());
  }

  @Test
  public void setsSignatureId() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");

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

    container.saveAsFile("src/test/resources/testFiles/tmp/testsetsSignatureId.bdoc");

    container = open("src/test/resources/testFiles/tmp/testsetsSignatureId.bdoc");
    assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    assertEquals("SIGNATURE-2", container.getSignature(1).getId());

    ZipFile zip = new ZipFile("src/test/resources/testFiles/tmp/testsetsSignatureId.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testSetsDefaultSignatureId.bdoc");

    container = open("src/test/resources/testFiles/tmp/testSetsDefaultSignatureId.bdoc");
    String signature1Id = container.getSignatures().get(0).getId();
    String signature2Id = container.getSignatures().get(1).getId();
    assertFalse(StringUtils.equals(signature1Id, signature2Id));
    assertTrue(signature1Id.startsWith("id-"));
    assertTrue(signature2Id.startsWith("id-"));

    ZipFile zip = new ZipFile("src/test/resources/testFiles/tmp/testSetsDefaultSignatureId.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void getDataFileByIndex() {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);

    assertEquals("test.txt", container.getDataFile(0).getName());
  }

  @Test(expected = DigiDoc4JException.class)
  public void openNonExistingFileThrowsError() {
    open("non-existing.bdoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void openClosedStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("src/test/resources/testFiles/helper-files/test.txt"));
    stream.close();
    open(stream, false);
  }

  @Test
  public void testLargeFileSigning() throws Exception {
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        build();
    container.getConfiguration().enableBigFilesSupport(10);
    String path = createLargeFile((container.getConfiguration().getMaxDataFileCachedInBytes()) + 100);
    container.addDataFile(path, "text/plain");
    signContainer(container);
  }

  @Test
  public void openLargeFileFromStream() throws IOException {
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        build();
    container.getConfiguration().enableBigFilesSupport(0);

    String path = createLargeFile((container.getConfiguration().getMaxDataFileCachedInBytes()) + 100);
    container.addDataFile(path, "text/plain");
    signContainer(container);
    container.save(path);
    File file = new File(path);
    FileInputStream fileInputStream = new FileInputStream(file);
    open(fileInputStream, true);

    IOUtils.closeQuietly(fileInputStream);

    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void openAddFileFromStream() throws IOException {
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        build();
    container.getConfiguration().enableBigFilesSupport(0);

    String path = createLargeFile((container.getConfiguration().getMaxDataFileCachedInBytes()) + 100);
    try (FileInputStream stream = new FileInputStream(new File(path))) {
      container.addDataFile(stream, "fileName", "text/plain");
      signContainer(container);
      container.save(path);
      File file = new File(path);
      FileInputStream fileInputStream = new FileInputStream(file);
      open(fileInputStream, true);
      IOUtils.closeQuietly(fileInputStream);
    }
    assertEquals(1, container.getSignatures().size());
  }

  private String createLargeFile(long size) throws IOException {
    String fileName = testFolder.newFolder().getAbsolutePath() + File.separator + "test_large_file.bdoc";
    try {
      RandomAccessFile largeFile = new RandomAccessFile(fileName, "rw");
      largeFile.setLength(size);// TODO: create large file correctly
    } catch (Exception e) {
      e.printStackTrace();
    }
    return fileName;
  }

  @Test
  public void testGetDocumentType() throws Exception {
    createSignedBDocDocument("src/test/resources/testFiles/tmp/testGetDocumentType.bdoc");
    Container container = open("src/test/resources/testFiles/tmp/testGetDocumentType.bdoc");
    assertEquals(Container.DocumentType.BDOC, container.getDocumentType());
  }

  @Test
  public void testAddTwoFilesAsStream() throws Exception {
    Container container = createEmptyBDocContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.addDataFile(stream, "test2.txt", "text/plain");
  }

  @Test
  public void testAddTwoFilesAsFileWithoutOCSP() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    signContainer(container, B_BES);
    container.save("src/test/resources/testFiles/tmp/testTwoFilesSigned.bdoc");

    container = open("src/test/resources/testFiles/tmp/testTwoFilesSigned.bdoc");
    assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void testGetFileNameAndID() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testTwoFilesSigned.bdoc");

    container = open("src/test/resources/testFiles/tmp/testTwoFilesSigned.bdoc");

    assertEquals("test.txt", container.getDataFile(0).getName());
    assertEquals("test.xml", container.getDataFile(1).getName());
    assertEquals("test.txt", container.getDataFile(0).getId());
    assertEquals("test.xml", container.getDataFile(1).getId());
  }

  @Test
  public void testAddTwoFilesAsFileWithOCSP() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testTwoFilesSigned.bdoc");

    container = open("src/test/resources/testFiles/tmp/testTwoFilesSigned.bdoc");
    assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void saveToStream() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "test_bytes.txt", "text/plain");
    signContainer(container);
    File expectedContainerAsFile = new File("src/test/resources/testFiles/tmp/testSaveToStreamTest.bdoc");
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    container.save(out);
    assertTrue(Files.exists(expectedContainerAsFile.toPath()));

    Container containerToTest = open(expectedContainerAsFile.getAbsolutePath());
    assertArrayEquals(new byte[]{0x42}, containerToTest.getDataFiles().get(0).getBytes());
  }

  @Test
  public void saveExistingContainerToStream() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    signContainer(container);
    assertEquals(3, container.getSignatures().size());
    InputStream inputStream = container.saveAsStream();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    IOUtils.copy(inputStream, outputStream);
    ByteArrayInputStream savedContainerStream = new ByteArrayInputStream(outputStream.toByteArray());
    container = open(savedContainerStream);
    assertEquals(3, container.getSignatures().size());
    assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void saveToStreamThrowsException() throws IOException {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    File expectedContainerAsFile = new File("src/test/resources/testFiles/tmp/testSaveToStreamTest.bdoc");
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    out.close();
    container.save(out);
  }

  @Test
  public void saveExistingContainer() throws Exception {
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    String containerPath = testFolder.newFile("test-container.asice").getPath();
    container.saveAsFile(containerPath);
    Container savedContainer = open(containerPath);
    assertTrue(savedContainer.validate().isValid());
    assertEquals(1, savedContainer.getDataFiles().size());
    assertEquals(2, savedContainer.getSignatures().size());
    ZipFile zip = new ZipFile(containerPath);
    assertNotNull(zip.getEntry("mimetype"));
    assertNotNull(zip.getEntry("test.txt"));
    assertNotNull(zip.getEntry("META-INF/manifest.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void containerIsLT() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container, LT);
    container.saveAsFile("src/test/resources/testFiles/tmp/testLT.bdoc");
    container = open("src/test/resources/testFiles/tmp/testLT.bdoc");
    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void verifySignatureProfileIsTS() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container, LT);
    container.saveAsFile("src/test/resources/testFiles/tmp/testAddConfirmation.bdoc");

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void signWithoutDataFile() throws Exception {
    Container container = createEmptyBDocContainer();
    signContainer(container);
  }

  @Test
  public void nonStandardMimeType() {
    Container container = ContainerBuilder.aContainer(BDOC_CONTAINER_TYPE).build();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/newtype");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testNonStandardMimeType.bdoc");
    container = ContainerOpener.open("src/test/resources/testFiles/tmp/testNonStandardMimeType.bdoc");
    ValidationResult result = container.validate();
    assertEquals(0, result.getErrors().size());
    assertEquals("text/newtype", container.getDataFile(0).getMediaType());
  }

  @Test
  public void getVersion() {
    Container container = createEmptyBDocContainer();
    assertEquals("", container.getVersion());
  }

  @Test
  public void twoStepSigning() throws IOException {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    X509Certificate signerCert = getSigningCert();
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert).
        buildDataToSign();
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile("src/test/resources/testFiles/tmp/test.bdoc");

    container = ContainerOpener.open("src/test/resources/testFiles/tmp/test.bdoc");

    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());

    assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", resultSignature.getSignatureMethod());
    assertThat(resultSignature.getSignerRoles(), is(empty()));
    assertEquals("", resultSignature.getCity());
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
    assertEquals(new String(Files.readAllBytes(Paths.get("src/test/resources/testFiles/helper-files/test.txt"))), new String(dataFile.getBytes()));
    assertEquals(15, dataFile.getFileSize());
    assertEquals("test.txt", dataFile.getId());
  }

  @Test
  public void twoStepSigningVerifySignatureParameters() {
    Container container = ContainerBuilder.aContainer(BDOC_CONTAINER_TYPE).build();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    X509Certificate signerCert = getSigningCert();
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
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile("src/test/resources/testFiles/tmp/test.bdoc");

    container = ContainerOpener.open("src/test/resources/testFiles/tmp/test.bdoc");
    assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", resultSignature.getSignatureMethod());
    assertEquals("employee", resultSignature.getSignerRoles().get(1));
    assertEquals("city", resultSignature.getCity());
    assertEquals("S99", resultSignature.getId());
  }

  @Test
  public void testContainerCreationAsTSA() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container, LTA);

    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  private Container createSignedBDocDocument(String fileName) {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
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

  @Test
  public void testBDocTM() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container, LT_TM);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void testBDocTS() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container, LT);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void containerWithBESProfileHasNoValidationErrors() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container, B_BES);

    assertEquals(B_BES, container.getSignatures().get(0).getProfile());
    assertNull(container.getSignature(0).getOCSPCertificate());
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
  }

  @Test
  public void signWithECCCertificate() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(new PKCS12SignatureToken("src/test/resources/testFiles/p12/ec-digiid.p12", "inno".toCharArray())).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).
        invokeSigning();
    container.addSignature(signature);
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void zipFileComment() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    container.save("src/test/resources/testFiles/tmp/testZipFileComment.bdoc");

    String expectedComment = Helper.createBDocUserAgent(SignatureProfile.LT_TM);
    ZipFile zipFile = new ZipFile("src/test/resources/testFiles/tmp/testZipFileComment.bdoc");
    assertEquals(expectedComment, zipFile.getEntry("mimetype").getComment());
    assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
    assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
    assertEquals(expectedComment, zipFile.getEntry("META-INF/signatures0.xml").getComment());
    assertEquals(expectedComment, zipFile.getEntry("test.txt").getComment());
  }

  @Test
  public void signingMoreThanTwoFiles() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt", "text/plain");
      //container.addDataFile("src/test/resources/testFiles/special-char-files/dds_колючей стерне.docx", "text/plain");
      container.addDataFile("src/test/resources/testFiles/special-char-files/dds_pakitud.zip", "text/plain");
      container.addDataFile("src/test/resources/testFiles/special-char-files/dds_SK.jpg", "text/plain");
      container.addDataFile("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf", "text/plain");

      signContainer(container);

      BDocSignature signature = (BDocSignature)container.getSignature(0);
      assertSignatureContains(signature, "dds_dds_JÜRIÖÖ € žŠ päev.txt");
      //assertSignatureContains(signature, "dds_колючей стерне.docx");
      assertSignatureContains(signature, "dds_pakitud.zip");
      assertSignatureContains(signature, "dds_SK.jpg");
      assertSignatureContains(signature, "dds_acrobat.pdf");
  }

  @Test
  public void signatureFileNamesShouldBeInSequence() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
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
    ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
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
    ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc");
    assertNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = open("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc");
    signContainer(container);
    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    zip = new ZipFile(containerPath);
    assertNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
  }

  @Test
  public void whenSigningContainer_withSignatureNameContainingNonNumericCharacters_shouldCreateSignatureFileName_inSequence() throws Exception {
    ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice");
    assertNotNull(zip.getEntry("META-INF/l77Tsignaturesn00B.xml"));
    assertNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = open("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice");
    signContainer(container, SignatureProfile.LT);
    signContainer(container, SignatureProfile.LT);
    String containerPath = testFolder.newFile("test-container.asice").getPath();
    container.saveAsFile(containerPath);
    zip = new ZipFile(containerPath);
    assertNotNull(zip.getEntry("META-INF/l77Tsignaturesn00B.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void whenOpeningContainer_withTwoDataFilesWithSameName_andWithSingleReferenceInManifest_shouldThrowException() {
    Container container = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/KS-19_IB-3721_bdoc21-TM-2fil-samename-1sig3.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST))
        .build();
  }

  @Test(expected = DigiDoc4JException.class)
  public void whenOpeningContainer_withTwoManifests_oneIsErroneous_shouldThrowException() {
    Container container = ContainerBuilder.aContainer()
      .fromExistingFile("src/test/resources/testFiles/invalid-containers/KS-10_manifest_topelt_bdoc21_TM.bdoc")
      .withConfiguration(new Configuration(Configuration.Mode.TEST))
      .build();
  }

  @Test
  public void whenExistingContainer_hasWrongMimeSlash_weShouldNotThrowException() {
    ValidationResult result = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/INC166120_wrong_mime_slash.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST))
        .build().validate();
    Assert.assertFalse("Container is not invalid", result.isValid());
  }
  
  @Test(expected = DigiDoc4JException.class)
  public void whenOpeningContainer_withSignatureInfo_butNoSignedDataObject_shouldThrowException() {
    Container container = ContainerBuilder.aContainer()
      .fromExistingFile("src/test/resources/testFiles/invalid-containers/3863_bdoc21_TM_no_datafile.bdoc")
      .withConfiguration(new Configuration(Configuration.Mode.TEST))
      .build();
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signingContainer_withFailedOcspResponse_shouldThrowException() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setSignOCSPRequests(true);
    configuration.setOCSPAccessCertificateFileName("src/test/resources/testFiles/p12/signout.p12");
    configuration.setOCSPAccessCertificatePassword("test".toCharArray());
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").
        build();

    signContainer(container, LT_TM);
  }

  /**
   * This is necessary for jDigidoc compatibility. This requirement not in BDoc specification
   */
  @Test
  public void bdocTM_OcspResponderCert_shouldContainResponderCertIdAttribute() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    BDocSignature signature = (BDocSignature) signContainer(container, LT_TM);
    XAdESSignature xAdESSignature = signature.getOrigin().getDssSignature();
    assertEquals(1, countOcspResponderCertificates(xAdESSignature));
  }

  @Test
  public void savingContainerWithoutSignatures_shouldNotThrowException() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    assertTrue(container.getSignatures().isEmpty());
    assertEquals(1, container.getDataFiles().size());
    assertTrue(container.validate().isValid());
    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    Container savedContainer = open(containerPath);
    assertTrue(savedContainer.getSignatures().isEmpty());
    assertEquals(1, container.getDataFiles().size());
    byte[] expectedDataFileBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] actualDataFileBytes = savedContainer.getDataFiles().get(0).getBytes();
    Assert.assertArrayEquals(expectedDataFileBytes, actualDataFileBytes);
  }

  @Test
  public void openBDoc_withoutCAConfiguration_shouldNotThrowException() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
    BDocContainer container = new BDocContainer("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", configuration);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void timeStampCertStatusDeprecated() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    BDocContainer container = new BDocContainer("src/test/resources/testFiles/invalid-containers/invalid-containers-23816_leedu_live_TS_authority.asice", configuration);
    ValidationResult validate = container.validate();
    assertFalse(validate.isValid());
  }

  private void assertSignatureContains(BDocSignature signature, String name) {
      assertNotNull(findSignedFile(signature, name));
  }

  private DSSDocument findSignedFile(BDocSignature signature, String name) {
      List<DSSDocument> signedFiles = signature.getOrigin().getDssSignature().getDetachedContents();
      for (DSSDocument signedFile : signedFiles) {
          if(name.equals(signedFile.getName())) {
              return signedFile;
          }
      }
      return null;
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
    return open(fileInputStream);
  }

  private Container open(InputStream fileInputStream) {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        fromStream(fileInputStream).
        build();
    return container;
  }

  private Container createContainerWithFile(String path, String mimeType) {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withDataFile(path, mimeType).
        build();
    return container;
  }

  private int countOcspResponderCertificates(XAdESSignature xAdESSignature) {
    XPathQueryHolder xPathQueryHolder = xAdESSignature.getXPathQueryHolder();
    String xPath = xPathQueryHolder.XPATH_CERTIFICATE_VALUES;
    Element certificateValues = DomUtils.getElement(xAdESSignature.getSignatureElement(), xPath);
    return countResponderCertIdInsCertificateValues(certificateValues);
  }

  private int countResponderCertIdInsCertificateValues(Element certificateValues) {
    int responderCertCount = 0;
    NodeList certificates = certificateValues.getChildNodes();
    for(int i = 0;i < certificates.getLength(); i++) {
      Node cert = certificates.item(i);
      Node certId = cert.getAttributes().getNamedItem("Id");
      if(certId != null) {
        String idValue = certId.getNodeValue();
        if(StringUtils.containsIgnoreCase(idValue, "RESPONDER_CERT")) {
          responderCertCount++;
        }
      }
    }
    return responderCertCount;
  }

  @Test
  public void settingUpOwnSignaturePolicy() throws Exception {
    String signatureId = "signatureId";
    byte[] digestValue = decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=");
    String qualifier = "qualifier";
    eu.europa.esig.dss.DigestAlgorithm digestAlgorithm = eu.europa.esig.dss.DigestAlgorithm.SHA256;
    String spuri = "spuri";

    Policy signaturePolicy = new Policy();
    signaturePolicy.setId(signatureId);
    signaturePolicy.setDigestValue(digestValue);
    signaturePolicy.setQualifier(qualifier);
    signaturePolicy.setDigestAlgorithm(digestAlgorithm);
    signaturePolicy.setSpuri(spuri);

    Container container = ContainerBuilder.aContainer().build();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withOwnSignaturePolicy(signaturePolicy).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).
        withSignatureToken(PKCS12_SIGNER).
        withSignatureProfile(SignatureProfile.LT_TM).
        invokeSigning();
    container.addSignature(signature);

    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    container = ContainerOpener.open(containerPath);

    BDocSignature bdocSignature = (BDocSignature) container.getSignatures().get(0);
    SignaturePolicy policyId = bdocSignature.getOrigin().getDssSignature().getPolicyId();

    assertEquals(spuri, policyId.getUrl());
    assertEquals(signatureId, policyId.getIdentifier());
    assertEquals(digestAlgorithm, policyId.getDigestAlgorithm());
    assertEquals("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=", policyId.getDigestValue());

  }

  @Test
  public void containerWithSignaturePolicyByDefault() throws Exception {

    Container container = ContainerBuilder.aContainer().build();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).
        withSignatureToken(PKCS12_SIGNER).
        withSignatureProfile(SignatureProfile.LT_TM).
        invokeSigning();
    container.addSignature(signature);

    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    container = ContainerOpener.open(containerPath);

    BDocSignature bdocSignature = (BDocSignature) container.getSignatures().get(0);
    SignaturePolicy policyId = bdocSignature.getOrigin().getDssSignature().getPolicyId();

    assertEquals("https://www.sk.ee/repository/bdoc-spec21.pdf", policyId.getUrl());
    assertEquals("" + XadesSignatureValidator.TM_POLICY, policyId.getIdentifier());
    assertEquals(eu.europa.esig.dss.DigestAlgorithm.SHA256, policyId.getDigestAlgorithm());
    assertEquals("0xRLPsW1UIpxtermnTGE+5+5620UsWi5bYJY76Di3o0=", policyId.getDigestValue());
  }
}
