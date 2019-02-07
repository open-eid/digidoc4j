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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.zip.ZipFile;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.digidoc4j.signers.PKCS11SignatureToken;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.utils.Helper;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class BDocContainerTest extends AbstractTest {

  @Test
  public void testSetDigestAlgorithmToSHA256() throws Exception {
    AsicESignature signature = this.createSignatureBy(DigestAlgorithm.SHA256, this.pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureDigestAlgorithm().getXmlId());
  }

  @Test
  public void testSetDigestAlgorithmToSHA1() throws Exception {
    AsicESignature signature = this.createSignatureBy(DigestAlgorithm.SHA1, this.pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", signature.getSignatureDigestAlgorithm().getXmlId());
  }

  @Test
  public void testSetDigestAlgorithmToSHA224() throws Exception {
    AsicESignature signature = this.createSignatureBy(DigestAlgorithm.SHA224, this.pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#sha224", signature.getSignatureDigestAlgorithm().getXmlId());
  }

  @Test
  public void testDefaultDigestAlgorithm() throws Exception {
    AsicESignature signature = this.createSignatureBy(Container.DocumentType.BDOC, this.pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureDigestAlgorithm().getXmlId());
  }

  @Test
  public void testOpenBDocDocument() throws Exception {
    ContainerOpener.open("src/test/resources/testFiles/valid-containers/one_signature.bdoc").validate();
  }

  @Test
  public void testOpenBDocDocumentWithTwoSignatures() throws Exception {
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc").validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileWhenFileDoesNotExist() throws Exception {
    this.createNonEmptyContainerBy(Paths.get("notExisting.txt"), "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileFromInputStreamWithByteArrayConversionFailure() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new InputStream() {

      @Override
      public int read() throws IOException {
        return 0;
      }

      @Override
      public int read(byte b[], int off, int len) throws IOException {
        throw new IOException();
      }

      @Override
      public void close() throws IOException {
        throw new IOException();
      }

    }, "test.txt", "text/plain");
  }

  @Test(expected = InvalidSignatureException.class)
  public void testAddRawSignature() throws Exception {
    this.createEmptyContainerBy(Container.DocumentType.BDOC, BDocContainer.class).addRawSignature(new byte[]{});
  }

  @Test
  public void testAddUnknownFileTypeKeepsMimeType() {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.unknown_type"), "text/test_type");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("text/test_type", container.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void testSaveBDocDocumentWithTwoSignatures() throws Exception {
    Container container = this.createNonEmptyContainerBy(Container.DocumentType.BDOC);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(1).getSigningCertificate().getSerial());
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(1).getSigningCertificate().getSerial());
  }

  @Test
  public void saveContainerWithoutSignatures() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
  }

  @Test
  public void openContainer_withoutSignatures_andAddMoreDataFiles() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    Assert.assertEquals(1, container.getDataFiles().size());
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    container.addDataFile("src/test/resources/testFiles/helper-files/word_file.docx", "application/octet-stream");
    Assert.assertEquals(3, container.getDataFiles().size());
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(3, container.getDataFiles().size());
  }

  @Test
  public void openContainerFromStream_withoutSignatures_andAddMoreDataFiles() throws Exception {
    try (FileInputStream stream = new FileInputStream("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc")) {
      Container container = ContainerOpener.open(stream, false);
      Assert.assertEquals(1, container.getDataFiles().size());
      container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
      container.addDataFile("src/test/resources/testFiles/helper-files/word_file.docx", "application/octet-stream");
      Assert.assertEquals(3, container.getDataFiles().size());
      String file = this.getFileBy("bdoc");
      container.saveAsFile(file);
      container = ContainerOpener.open(new FileInputStream(file), false);
      Assert.assertEquals(3, container.getDataFiles().size());
    }
  }

  @Test
  public void openContainerWithoutSignatures_addDataFileAndSignContainer() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    Assert.assertEquals(1, container.getDataFiles().size());
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertTrue(container.validate().isValid());
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testGetDefaultSignatureParameters() {
    Container container = this.createNonEmptyContainerBy(Container.DocumentType.BDOC);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Signature signature = container.getSignature(0);
    Assert.assertEquals("", signature.getPostalCode());
    Assert.assertEquals("", signature.getCity());
    Assert.assertEquals("", signature.getStateOrProvince());
    Assert.assertEquals("", signature.getCountryName());
    Assert.assertThat(signature.getSignerRoles(), Matchers.is(Matchers.empty()));
  }

  @Test
  public void getSignatureByIndex() {
    Container container = this.createNonEmptyContainerBy(Container.DocumentType.BDOC);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c", container.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test
  public void notThrowingNPEWhenDOCXFileIsAddedToContainer() {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/word_file.docx"), "text/xml");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void signPdfDataFile() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf"), "application/pdf");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertEquals(1, container.getSignatures().size());
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testAddSignaturesToExistingDocument() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    Assert.assertEquals(3, container.getSignatures().size());
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(2).getSigningCertificate().getSerial());
    container = ContainerOpener.open(file);
    Assert.assertEquals(3, container.getSignatures().size());
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c",
        container.getSignatures().get(2).getSigningCertificate().getSerial());
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  @Test
  public void testRemoveSignatureWhenOneSignatureExists() throws Exception {
    Container container = this.createNonEmptyContainerBy(Container.DocumentType.BDOC);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    container.removeSignature(0);
    String file = this.getFileBy("bdoc");
    container.save(file);
    Assert.assertEquals(0, container.getSignatures().size());
    container = ContainerOpener.open(file);
    Assert.assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void testAddFilesWithSpecialCharactersIntoContainer() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt"), "text/plain");
    //container.addDataFile("src/test/resources/testFiles/special-char-files/dds_колючей стерне.docx", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    container.saveAsFile(this.getFileBy("bdoc"));
    Assert.assertEquals(0, container.validate().getContainerErrors().size());
  }

  @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    Assert.assertEquals(2, container.getSignatures().size());
    container.removeSignature(0);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenThreeSignaturesExist() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(3, container.getSignatures().size());
    container.removeSignature(1);
    file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void removeNewlyAddedSignatureFromExistingContainer() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    Assert.assertEquals(2, container.getSignatures().size());
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals(3, container.getSignatures().size());
    container.removeSignature(container.getSignatures().get(0));
    Assert.assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void removeSignatureFromExistingContainer() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    Assert.assertEquals(2, container.getSignatures().size());
    container.removeSignature(container.getSignatures().get(0));
    Assert.assertEquals(1, container.getSignatures().size());
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testSaveDocumentWithOneSignature() throws Exception {
    Assert.assertTrue(Files.exists(Paths.get(this.createSignedContainerBy("bdoc"))));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemoveDataFileAfterSigning() throws Exception {
    Container container = ContainerOpener.open(this.createSignedContainerBy("bdoc"));
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Assert.assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    Assert.assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testRemoveDataFile() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Assert.assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    Assert.assertEquals(0, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileAfterSigning() throws Exception {
    Container container = ContainerOpener.open(this.createSignedContainerBy("bdoc"));
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNonExistingFile() throws Exception {
    Container container = this.createNonEmptyContainer();
    container.removeDataFile("test1.txt");
  }


  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileSeveralTimes() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSamePreCreatedFileSeveralTimes() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    DataFile dataFile = new DataFile("Hello world!".getBytes(), "test-file.txt", "text/plain");
    container.addDataFile(dataFile);
    container.addDataFile(dataFile);
  }

  @Test
  public void testAddingDifferentPreCreatedFiles() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new DataFile("Hello world!".getBytes(), "hello.txt", "text/plain"));
    container.addDataFile(new DataFile("Goodbye world!".getBytes(), "goodbye.txt", "text/plain"));
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileSeveralTimesViaInputStream() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test
  public void testAddDateFileViaInputStream() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test(expected = DuplicateDataFileException.class)
  public void testAddingSameFileInDifferentContainerSeveralTimes() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    container.save(this.getFileBy("bdoc"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingNotExistingFile() throws Exception {
    this.createNonEmptyContainerBy(Paths.get("notExistingFile.txt"), "text/plain");
  }

  @Test
  public void testAddFileAsStream() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    Container containerToTest = ContainerOpener.open(file);
    Assert.assertEquals("test1.txt", containerToTest.getDataFiles().get(0).getName());
  }

  @Test
  public void setsSignatureId() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    Signature signature1 = SignatureBuilder.aSignature(container).withSignatureId("SIGNATURE-1").
        withSignatureToken(this.pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature1);
    Signature signature2 = SignatureBuilder.aSignature(container).withSignatureId("SIGNATURE-2").
        withSignatureToken(this.pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature2);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    Assert.assertEquals("SIGNATURE-2", container.getSignature(1).getId());
    ZipFile zip = new ZipFile(file);
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    String signature1Id = container.getSignatures().get(0).getId();
    String signature2Id = container.getSignatures().get(1).getId();
    Assert.assertFalse(StringUtils.equals(signature1Id, signature2Id));
    Assert.assertTrue(signature1Id.startsWith("id-"));
    Assert.assertTrue(signature2Id.startsWith("id-"));
    ZipFile zip = new ZipFile(file);
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void getDataFileByIndex() {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals("test.txt", container.getDataFile(0).getName());
  }

  @Test(expected = DigiDoc4JException.class)
  public void openNonExistingFileThrowsError() {
    ContainerOpener.open("non-existing.bdoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void openClosedStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("src/test/resources/testFiles/helper-files/test.txt"));
    stream.close();
    ContainerOpener.open(stream, false);
  }

  @Test
  public void testLargeFileSigning() throws Exception {
    BDocContainer container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC)
        .withConfiguration(new Configuration(Configuration.Mode.TEST)).build();
    container.getConfiguration().enableBigFilesSupport(10);
    container.addDataFile(this.createNonEmptyLargeContainer(container.getConfiguration().getMaxDataFileCachedInBytes() + 100), "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
  }

  @Test
  public void openLargeFileFromStream() throws IOException {
    BDocContainer container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC).
        withConfiguration(new Configuration(Configuration.Mode.TEST)).build();
    container.getConfiguration().enableBigFilesSupport(0);
    String file = this.createNonEmptyLargeContainer(container.getConfiguration().getMaxDataFileCachedInBytes() + 100);
    container.addDataFile(file, "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    container.save(file);
    try (FileInputStream stream = new FileInputStream(new File(file))) {
      ContainerOpener.open(stream, true);
    }
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void openAddFileFromStream() throws IOException {
    BDocContainer container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.getConfiguration().enableBigFilesSupport(0);
    String file = this.createNonEmptyLargeContainer(container.getConfiguration().getMaxDataFileCachedInBytes() + 100);
    try (FileInputStream stream = new FileInputStream(new File(file))) {
      container.addDataFile(stream, "fileName", "text/plain");
      this.createSignatureBy(container, this.pkcs12SignatureToken);
      container.save(file);
      FileInputStream stream2 = new FileInputStream(new File(file));
      ContainerOpener.open(stream2, true);
      IOUtils.closeQuietly(stream2);
    }
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testGetDocumentType() throws Exception {
    Container container = ContainerOpener.open(this.createSignedContainerBy("bdoc"));
    Assert.assertEquals(Container.DocumentType.BDOC, container.getDocumentType());
  }

  @Test
  public void testAddTwoFilesAsStream() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.addDataFile(stream, "test2.txt", "text/plain");
  }

  @Test
  public void testAddTwoFilesAsFileWithoutOCSP() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void testGetFileNameAndID() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("test.txt", container.getDataFile(0).getName());
    Assert.assertEquals("test.xml", container.getDataFile(1).getName());
    Assert.assertEquals("test.txt", container.getDataFile(0).getId());
    Assert.assertEquals("test.xml", container.getDataFile(1).getId());
  }

  @Test
  public void testAddTwoFilesAsFileWithOCSP() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void saveToStream() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "test_bytes.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    File expectedContainerAsFile = new File(this.getFileBy("bdoc"));
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    container.save(out);
    Assert.assertTrue(Files.exists(expectedContainerAsFile.toPath()));
    Container containerToTest = ContainerOpener.open(expectedContainerAsFile.getAbsolutePath());
    Assert.assertArrayEquals(new byte[]{0x42}, containerToTest.getDataFiles().get(0).getBytes());
  }

  @Test
  public void saveExistingContainerToStream() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals(3, container.getSignatures().size());
    InputStream inputStream = container.saveAsStream();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    IOUtils.copy(inputStream, outputStream);
    ByteArrayInputStream savedContainerStream = new ByteArrayInputStream(outputStream.toByteArray());
    container = ContainerOpener.open(savedContainerStream, false);
    Assert.assertEquals(3, container.getSignatures().size());
    Assert.assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void saveToStreamThrowsException() throws IOException {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    File expectedContainerAsFile = new File(this.getFileBy("bdoc"));
    OutputStream out = new FileOutputStream(expectedContainerAsFile);
    out.close();
    container.save(out);
  }

  @Test
  public void saveExistingContainer() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    String file = this.getFileBy("asice");
    container.saveAsFile(file);
    Container savedContainer = ContainerOpener.open(file);
    Assert.assertTrue(savedContainer.validate().isValid());
    Assert.assertEquals(1, savedContainer.getDataFiles().size());
    Assert.assertEquals(2, savedContainer.getSignatures().size());
    ZipFile zip = new ZipFile(file);
    Assert.assertNotNull(zip.getEntry("mimetype"));
    Assert.assertNotNull(zip.getEntry("test.txt"));
    Assert.assertNotNull(zip.getEntry("META-INF/manifest.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test
  public void containerIsLT() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void signWithoutDataFile() throws Exception {
    this.createSignatureBy(this.createEmptyContainerBy(Container.DocumentType.BDOC, Container.class), this.pkcs12SignatureToken);
  }

  @Test
  public void nonStandardMimeType() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/newtype");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    container = ContainerOpener.open(file);
    SignatureValidationResult result = container.validate();
    Assert.assertEquals(0, result.getErrors().size());
    Assert.assertEquals("text/newtype", container.getDataFile(0).getMediaType());
  }

  @Test
  public void getVersion() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    Assert.assertEquals("", container.getVersion());
  }

  @Test
  public void twoStepSigning() throws IOException {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container).
        withSigningCertificate(this.pkcs12SignatureToken.getCertificate()).buildDataToSign();
    Signature signature = dataToSign.finalize(this.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm()));
    container.addSignature(signature);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertTrue(container.validate().isValid());
    Assert.assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", resultSignature.getSignatureMethod());
    Assert.assertThat(resultSignature.getSignerRoles(), Matchers.is(Matchers.empty()));
    Assert.assertEquals("", resultSignature.getCity());
    Assert.assertTrue(StringUtils.isNotBlank(resultSignature.getId()));
    Assert.assertNotNull(resultSignature.getOCSPCertificate());
    Assert.assertNotNull(resultSignature.getSigningCertificate());
    Assert.assertNotNull(resultSignature.getAdESSignature().length);
    Assert.assertEquals(SignatureProfile.LT, resultSignature.getProfile());
    Assert.assertNotNull(resultSignature.getTimeStampTokenCertificate());
    List<DataFile> dataFiles = container.getDataFiles();
    Assert.assertEquals(1, dataFiles.size());
    DataFile dataFile = dataFiles.get(0);
    Assert.assertEquals("test.txt", dataFile.getName());
    dataFile.calculateDigest(DigestAlgorithm.SHA384);
    Assert.assertEquals("text/plain", dataFile.getMediaType());
    Assert.assertEquals(new String(Files.readAllBytes(Paths.get("src/test/resources/testFiles/helper-files/test.txt"))), new String(dataFile.getBytes()));
    Assert.assertEquals(15, dataFile.getFileSize());
    Assert.assertEquals("test.txt", dataFile.getId());
  }

  @Test
  public void twoStepSigningVerifySignatureParameters() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).build();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).withSigningCertificate(this.pkcs12SignatureToken.getCertificate()).
        withSignatureId("S99").withRoles("manager", "employee").withCity("city").withStateOrProvince("state").
        withPostalCode("postalCode").withCountry("country").buildDataToSign();
    byte[] signatureValue = this.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignature(0);
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", resultSignature.getSignatureMethod());
    Assert.assertEquals("employee", resultSignature.getSignerRoles().get(1));
    Assert.assertEquals("city", resultSignature.getCity());
    Assert.assertEquals("S99", resultSignature.getId());
  }

  @Test
  public void testContainerCreationAsTSA() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, SignatureProfile.LTA, this.pkcs12SignatureToken);
    Assert.assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void testBDocTM() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testBDocTS() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void containerWithBESProfileHasNoValidationErrors() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    Assert.assertEquals(SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
    Assert.assertNull(container.getSignature(0).getOCSPCertificate());
    Assert.assertFalse(container.validate().isValid());
  }

  @Test
  public void signWithECCCertificate() throws Exception {
    Container container = this.createNonEmptyContainerBy(Container.DocumentType.BDOC);
    Signature signature = SignatureBuilder.aSignature(container).
        withSignatureToken(new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray())).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).invokeSigning();
    container.addSignature(signature);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void zipFileComment() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
    String expectedComment = Helper.createBDocUserAgent(SignatureProfile.LT);
    ZipFile zipFile = new ZipFile(file);
    Assert.assertEquals(expectedComment, zipFile.getEntry("mimetype").getComment());
    Assert.assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
    Assert.assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
    Assert.assertEquals(expectedComment, zipFile.getEntry("META-INF/signatures0.xml").getComment());
    Assert.assertEquals(expectedComment, zipFile.getEntry("test.txt").getComment());
  }

  @Test
  public void signingMoreThanTwoFiles() throws Exception {
    Container container = this.createNonEmptyContainerBy(Container.DocumentType.BDOC,
        Paths.get("src/test/resources/testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt"),
        "text/plain");
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_pakitud.zip", "text/plain");
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_SK.jpg", "text/plain");
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Signature signature = container.getSignature(0);
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_dds_JÜRIÖÖ € žŠ päev.txt");
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_pakitud.zip");
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_SK.jpg");
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_acrobat.pdf");
  }

  @Test
  public void signatureFileNamesShouldBeInSequence() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    ZipFile zip = new ZipFile(file);
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
  }

  @Test
  public void whenSigningExistingContainer_withTwoSignatures_shouldCreateSignatureFileName_signatures2() throws Exception {
    ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    zip = new ZipFile(file);
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
  }

  @Test
  public void whenSigningExistingContainer_with_signatures1_xml_shouldCreateSignatureFileName_signatures2() throws Exception {
    ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc");
    Assert.assertNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    zip = new ZipFile(file);
    Assert.assertNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
  }

  @Test(expected = TechnicalException.class)
  public void addSingatureWithDuplicateId_throwsException() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/test.asice");
    Signature signature = SignatureBuilder.aSignature(container).
            withSignatureToken(this.pkcs12SignatureToken).withSignatureId("S0").invokeSigning();
    container.addSignature(signature);
  }

  @Test
  public void whenSigningContainer_withSignatureNameContainingNonNumericCharacters_shouldCreateSignatureFileName_inSequence() throws Exception {
    ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice");
    Assert.assertNotNull(zip.getEntry("META-INF/l77Tsignaturesn00B.xml"));
    Assert.assertNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNull(zip.getEntry("META-INF/signatures1.xml"));
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice");
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    zip = new ZipFile(file);
    Assert.assertNotNull(zip.getEntry("META-INF/l77Tsignaturesn00B.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void whenOpeningContainer_withTwoDataFilesWithSameName_andWithSingleReferenceInManifest_shouldThrowException() {
    ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/KS-19_IB-3721_bdoc21-TM-2fil-samename-1sig3.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST)).build();
  }

  @Test(expected = DigiDoc4JException.class)
  public void whenOpeningContainer_withTwoManifests_oneIsErroneous_shouldThrowException() {
    ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/KS-10_manifest_topelt_bdoc21_TM.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST)).build();
  }

  @Test
  public void whenExistingContainer_hasWrongMimeSlash_weShouldNotThrowException() {
    SignatureValidationResult result = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/INC166120_wrong_mime_slash.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST)).build().validate();
    Assert.assertFalse("Container is not invalid", result.isValid());
  }

  @Test(expected = DigiDoc4JException.class)
  public void whenOpeningContainer_withSignatureInfo_butNoSignedDataObject_shouldThrowException() {
    ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/3863_bdoc21_TM_no_datafile.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST)).build();
  }

  @Test
  public void whenOpeningContainer_withSignaturePolicyImpliedElement_inTMSignatures_shouldThrowException() {
    SignatureValidationResult result = ContainerBuilder.aContainer()
        .fromExistingFile(
            "src/test/resources/prodFiles/invalid-containers/23608_bdoc21-invalid-nonce-policy-and-implied.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.PROD)).build().validate();
    Assert.assertFalse("Container should be invalid", result.isValid());
    Assert.assertEquals("Incorrect errors count", 1, result.getErrors().size());
    Assert.assertEquals("(Signature ID: S0) - Signature contains forbidden <SignaturePolicyImplied> element",
        result.getErrors().get(0).toString());
  }

  @Test
  @Ignore("Fix by adding AdditionalServiceInformation to TEST of ESTEID-SK 2015 in test TSL")
  public void containerWithImplicitPolicy(){
    setGlobalMode(Configuration.Mode.TEST);
    Container container = ContainerOpener.open
        ("src/test/resources/testFiles/valid-containers/validTSwImplicitPolicy.asice");
    ContainerValidationResult validate = container.validate();
    Assert.assertTrue(validate.isValid());
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void signingContainer_withFailedOcspResponse_shouldThrowException() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setSignOCSPRequests(true);
    configuration.setOCSPAccessCertificateFileName("src/test/resources/testFiles/p12/signout.p12");
    configuration.setOCSPAccessCertificatePassword("test".toCharArray());
    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).withConfiguration(configuration).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").build();
    this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
  }

  @Test
  public void bdocTM_OcspResponderCert_shouldContainResponderCertIdAttribute() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    BDocSignature signature = this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    Assert.assertEquals(1, this.countOCSPResponderCertificates(signature.getOrigin().getDssSignature()));
  }

  @Test
  public void savingContainerWithoutSignatures_shouldNotThrowException() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Assert.assertTrue(container.getSignatures().isEmpty());
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertTrue(container.validate().isValid());
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    Container savedContainer = ContainerOpener.open(file);
    Assert.assertTrue(savedContainer.getSignatures().isEmpty());
    Assert.assertEquals(1, container.getDataFiles().size());
    byte[] expectedDataFileBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] actualDataFileBytes = savedContainer.getDataFiles().get(0).getBytes();
    Assert.assertArrayEquals(expectedDataFileBytes, actualDataFileBytes);
  }

  @Test
  public void openBDoc_withoutCAConfiguration_shouldNotThrowException() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
    BDocContainer container = new BDocContainer("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", this.configuration);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void timeStampCertStatusDeprecated() throws Exception {
    BDocContainer container = new BDocContainer("src/test/resources/testFiles/invalid-containers/invalid-containers-23816_leedu_live_TS_authority.asice", new Configuration(Configuration.Mode.PROD));
    Assert.assertFalse(container.validate().isValid());
  }

  @Test
  public void settingUpOwnSignaturePolicy() throws Exception {
    String signatureId = "signatureId";
    byte[] digestValue = Base64.decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=");
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
    Signature signature = SignatureBuilder.aSignature(container).withOwnSignaturePolicy(signaturePolicy).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).withSignatureToken(this.pkcs12SignatureToken).
        withSignatureProfile(SignatureProfile.LT_TM).invokeSigning();
    container.addSignature(signature);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    BDocSignature bdocSignature = (BDocSignature) container.getSignatures().get(0);
    SignaturePolicy policyId = bdocSignature.getOrigin().getDssSignature().getPolicyId();
    Assert.assertEquals(spuri, policyId.getUrl());
    Assert.assertEquals(signatureId, policyId.getIdentifier());
    Assert.assertEquals(digestAlgorithm, policyId.getDigestAlgorithm());
    Assert.assertEquals("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=", policyId.getDigestValue());
  }

  @Test
  public void containerWithSignaturePolicyByDefault() throws Exception {
    Container container = ContainerBuilder.aContainer().build();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).
        withSignatureToken(this.pkcs12SignatureToken).withSignatureProfile(SignatureProfile.LT_TM).invokeSigning();
    container.addSignature(signature);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    BDocSignature bdocSignature = (BDocSignature) container.getSignatures().get(0);
    SignaturePolicy policyId = bdocSignature.getOrigin().getDssSignature().getPolicyId();
    Assert.assertEquals("https://www.sk.ee/repository/bdoc-spec21.pdf", policyId.getUrl());
    Assert.assertEquals("" + XadesSignatureValidator.TM_POLICY, policyId.getIdentifier());
    Assert.assertEquals(eu.europa.esig.dss.DigestAlgorithm.SHA256, policyId.getDigestAlgorithm());
    Assert.assertEquals("7pudpH4eXlguSZY2e/pNbKzGsq+fu//woYL1SZFws1A=", policyId.getDigestValue());
  }

  /*
   * RESTRICTED METHODS
   */

  private int countOCSPResponderCertificates(XAdESSignature signature) {
    return this.countResponderCertIdInsCertificateValues(DomUtils.getElement(signature.getSignatureElement(),
        signature.getXPathQueryHolder().XPATH_CERTIFICATE_VALUES));
  }

  private int countResponderCertIdInsCertificateValues(Element certificateValues) {
    int responderCertCount = 0;
    NodeList certificates = certificateValues.getChildNodes();
    for (int i = 0; i < certificates.getLength(); i++) {
      Node cert = certificates.item(i);
      Node certId = cert.getAttributes().getNamedItem("Id");
      if (certId != null) {
        String idValue = certId.getNodeValue();
        if (StringUtils.containsIgnoreCase(idValue, "RESPONDER_CERT")) {
          responderCertCount++;
        }
      }
    }
    return responderCertCount;
  }

}
