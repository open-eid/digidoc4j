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

import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.DuplicateSignatureFilesException;
import org.digidoc4j.exceptions.IllegalSignatureProfileException;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.test.TestAssert;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.zip.ZipFile;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertThrows;

public class BDocContainerTest extends AbstractTest {

  @Test
  public void testSetDigestAlgorithmToSHA256() {
    AsicESignature signature = createSignatureBy(DigestAlgorithm.SHA256, pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureDigestAlgorithm().getUri());
  }

  @Test
  public void testSetDigestAlgorithmToSHA1() {
    AsicESignature signature = createSignatureBy(DigestAlgorithm.SHA1, pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", signature.getSignatureDigestAlgorithm().getUri());
  }

  @Test
  public void testSetDigestAlgorithmToSHA224() {
    AsicESignature signature = createSignatureBy(DigestAlgorithm.SHA224, pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#sha224", signature.getSignatureDigestAlgorithm().getUri());
  }

  @Test
  public void testDefaultDigestAlgorithm() {
    AsicESignature signature = createSignatureBy(Container.DocumentType.BDOC, pkcs12SignatureToken);
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureDigestAlgorithm().getUri());
  }

  @Test
  public void testOpenBDocDocument() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/one_signature.bdoc");

    assertThat(container.getSignatures(), hasSize(1));
  }

  @Test
  public void testOpenBDocDocumentWithTwoSignatures() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc");

    assertThat(container.getSignatures(), hasSize(2));
  }

  @Test
  public void testAddDataFileWhenFileDoesNotExist() {
    assertThrows(
            InvalidDataFileException.class,
            () -> createNonEmptyContainerBy(Paths.get("notExisting.txt"), "text/plain")
    );
  }

  @Test
  public void testAddDataFileFromInputStreamWithByteArrayConversionFailure() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    assertThrows(
            InvalidDataFileException.class,
            () -> container.addDataFile(new InputStream() {

              @Override
              public int read() {
                return 0;
              }

              @Override
              public int read(byte[] b, int off, int len) throws IOException {
                throw new IOException();
              }

              @Override
              public void close() throws IOException {
                throw new IOException();
              }

            }, "test.txt", "text/plain")
    );
  }

  @Test
  public void testAddUnknownFileTypeKeepsMimeType() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.unknown_type"), "text/test_type");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("text/test_type", container.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void testSaveBDocDocumentWithTwoSignatures() {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC);
    createSignatureBy(container, pkcs12SignatureToken);
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals("6ec00b8b8c54c4f76082bd843e3a1526",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    Assert.assertEquals("6ec00b8b8c54c4f76082bd843e3a1526",
        container.getSignatures().get(1).getSigningCertificate().getSerial());
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals("6ec00b8b8c54c4f76082bd843e3a1526",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    Assert.assertEquals("6ec00b8b8c54c4f76082bd843e3a1526",
        container.getSignatures().get(1).getSigningCertificate().getSerial());
  }

  @Test
  public void saveContainerWithoutSignatures() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
  }

  @Test
  public void openContainer_withoutSignatures_andAddMoreDataFiles() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    Assert.assertEquals(1, container.getDataFiles().size());
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    container.addDataFile("src/test/resources/testFiles/helper-files/word_file.docx", "application/octet-stream");
    Assert.assertEquals(3, container.getDataFiles().size());
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(3, container.getDataFiles().size());
  }

  @Test
  public void openContainerFromStream_withoutSignatures_andAddMoreDataFiles() throws Exception {
    String file = getFileBy("bdoc");
    try (FileInputStream stream = new FileInputStream("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc")) {
      Container container = ContainerOpener.open(stream, false);
      Assert.assertEquals(1, container.getDataFiles().size());
      container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
      container.addDataFile("src/test/resources/testFiles/helper-files/word_file.docx", "application/octet-stream");
      Assert.assertEquals(3, container.getDataFiles().size());
      container.saveAsFile(file);
    }
    try (FileInputStream stream = new FileInputStream(file)) {
      Container container = ContainerOpener.open(stream, false);
      Assert.assertEquals(3, container.getDataFiles().size());
    }
  }

  @Test
  public void openContainerWithoutSignatures_addDataFileAndSignContainer() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc");
    Assert.assertEquals(1, container.getDataFiles().size());
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertTrue(container.validate().isValid());
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testGetDefaultSignatureParameters() {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC);
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals("", signature.getPostalCode());
    Assert.assertEquals("", signature.getCity());
    Assert.assertEquals("", signature.getStateOrProvince());
    Assert.assertEquals("", signature.getCountryName());
    assertThat(signature.getSignerRoles(), empty());
  }

  @Test
  public void getSignatureByIndex() {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC);
    createSignatureBy(container, pkcs12SignatureToken);
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals("6ec00b8b8c54c4f76082bd843e3a1526", container.getSignatures().get(1).getSigningCertificate().getSerial());
  }

  @Test
  public void notThrowingNPEWhenDOCXFileIsAddedToContainer() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/word_file.docx"), "text/xml");
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void signPdfDataFile() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf"), "application/pdf");
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertEquals(1, container.getSignatures().size());
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testAddSignaturesToExistingDocument() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    Assert.assertEquals(3, container.getSignatures().size());
    Assert.assertEquals("6ec00b8b8c54c4f76082bd843e3a1526",
        container.getSignatures().get(2).getSigningCertificate().getSerial());
    container = ContainerOpener.open(file);
    Assert.assertEquals(3, container.getSignatures().size());
    Assert.assertEquals("6ec00b8b8c54c4f76082bd843e3a1526",
        container.getSignatures().get(2).getSigningCertificate().getSerial());
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  @Test
  public void testRemoveSignatureWhenOneSignatureExists() {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC);
    createSignatureBy(container, pkcs12SignatureToken);
    Signature signature = container.getSignatures().get(0);
    container.removeSignature(signature);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    Assert.assertEquals(0, container.getSignatures().size());
    container = ContainerOpener.open(file);
    Assert.assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void testAddFilesWithSpecialCharactersIntoContainer() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt"), "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    container.saveAsFile(getFileBy("bdoc"));
    Assert.assertEquals(0, container.validate().getContainerErrors().size());
  }

  @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    Assert.assertEquals(2, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);
    container.removeSignature(signature);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenThreeSignaturesExist() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(3, container.getSignatures().size());
    Signature signature = container.getSignatures().get(1);
    container.removeSignature(signature);
    file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void removeNewlyAddedSignatureFromExistingContainer() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    Assert.assertEquals(2, container.getSignatures().size());
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals(3, container.getSignatures().size());
    container.removeSignature(container.getSignatures().get(0));
    Assert.assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void removeSignatureFromExistingAsicEContainer() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    Assert.assertEquals(2, container.getSignatures().size());
    container.removeSignature(container.getSignatures().get(0));
    Assert.assertEquals(1, container.getSignatures().size());
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void removeSignatureFromExistingBDocTMContainer() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    Assert.assertEquals(1, container.getSignatures().size());
    container.removeSignature(container.getSignatures().get(0));
    Assert.assertEquals(0, container.getSignatures().size());
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void removingNullSignatureDoesNothing() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    Assert.assertEquals(1, container.getSignatures().size());
    container.removeSignature(null);
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testSaveDocumentWithOneSignature() {
    Assert.assertTrue(Files.exists(Paths.get(createSignedContainerBy(Container.DocumentType.BDOC, "bdoc"))));
  }

  @Test
  public void testRemoveDataFileAfterSigning() {
    Container container = ContainerOpener.open(createSignedContainerBy(Container.DocumentType.BDOC, "bdoc"));
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Assert.assertEquals(1, container.getDataFiles().size());
    DataFile dataFileToRemove = container.getDataFiles().get(0);

    RemovingDataFileException caughtException = assertThrows(
            RemovingDataFileException.class,
            () -> container.removeDataFile(dataFileToRemove)
    );

    assertThat(caughtException.getMessage(), equalTo("Datafiles cannot be removed from an already signed container"));
  }

  @Test
  public void testRemoveDataFile() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Assert.assertEquals(1, container.getDataFiles().size());
    container.removeDataFile(container.getDataFiles().get(0));
    Assert.assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testAddDataFileAfterSigning() {
    Container container = ContainerOpener.open(createSignedContainerBy(Container.DocumentType.BDOC, "bdoc"));

    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain")
    );

    assertThat(caughtException.getMessage(), equalTo("Datafiles cannot be added to an already signed container"));
  }

  @Test
  public void testRemovingNonExistingFile() {
    Container container = createNonEmptyContainer();
    DataFile dataFileToRemove = new DataFile(new byte[1], "test1.txt", "application/octet-stream");

    DataFileNotFoundException caughtException = assertThrows(
            DataFileNotFoundException.class,
            () -> container.removeDataFile(dataFileToRemove)
    );

    assertThat(caughtException.getMessage(), equalTo("File not found: test1.txt"));
  }


  @Test
  public void testAddingSameFileSeveralTimes() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");

    DuplicateDataFileException caughtException = assertThrows(
            DuplicateDataFileException.class,
            () -> container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain")
    );

    assertThat(caughtException.getMessage(), equalTo("Data file test.txt already exists"));
  }

  @Test
  public void testAddingSamePreCreatedFileSeveralTimes() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    DataFile dataFile = new DataFile("Hello world!".getBytes(), "test-file.txt", "text/plain");
    container.addDataFile(dataFile);

    DuplicateDataFileException caughtException = assertThrows(
            DuplicateDataFileException.class,
            () -> container.addDataFile(dataFile)
    );

    assertThat(caughtException.getMessage(), equalTo("Data file test-file.txt already exists"));
  }

  @Test
  public void testAddingDifferentPreCreatedFiles() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new DataFile("Hello world!".getBytes(), "hello.txt", "text/plain"));
    container.addDataFile(new DataFile("Goodbye world!".getBytes(), "goodbye.txt", "text/plain"));
  }

  @Test
  public void testAddingSameFileSeveralTimesViaInputStream() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream("test".getBytes());

    DuplicateDataFileException caughtException = assertThrows(
            DuplicateDataFileException.class,
            () -> container.addDataFile(byteArrayInputStream, "src/test/resources/testFiles/helper-files/test.txt", "text/plain")
    );

    assertThat(caughtException.getMessage(), equalTo("Data file test.txt already exists"));
  }

  @Test
  public void testAddDateFileViaInputStream() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream("test".getBytes()), "src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testAddingSameFileInDifferentContainerSeveralTimes() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");

    DuplicateDataFileException caughtException = assertThrows(
            DuplicateDataFileException.class,
            () -> container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain")
    );

    assertThat(caughtException.getMessage(), equalTo("Data file test.txt already exists"));
  }

  @Test
  public void testAddingNotExistingFile() {
    assertThrows(
            InvalidDataFileException.class,
            () -> createNonEmptyContainerBy(Paths.get("notExistingFile.txt"), "text/plain")
    );
  }

  @Test
  public void testAddFileAsStream() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    Container containerToTest = ContainerOpener.open(file);
    Assert.assertEquals("test1.txt", containerToTest.getDataFiles().get(0).getName());
  }

  @Test
  public void setsSignatureId() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    Signature signature1 = SignatureBuilder.aSignature(container).withSignatureId("SIGNATURE-1").
        withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature1);
    Signature signature2 = SignatureBuilder.aSignature(container).withSignatureId("SIGNATURE-2").
        withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature2);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("SIGNATURE-1", container.getSignatures().get(0).getId());
    Assert.assertEquals("SIGNATURE-2", container.getSignatures().get(1).getId());
    try (ZipFile zip = new ZipFile(file)) {
      Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    }
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    String signature1Id = container.getSignatures().get(0).getId();
    String signature2Id = container.getSignatures().get(1).getId();
    Assert.assertFalse(StringUtils.equals(signature1Id, signature2Id));
    Assert.assertTrue(signature1Id.startsWith("id-"));
    Assert.assertTrue(signature2Id.startsWith("id-"));
    try (ZipFile zip = new ZipFile(file)) {
      Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    }
  }

  @Test
  public void getDataFileByIndex() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
  }

  @Test
  public void openNonExistingFileThrowsError() {
    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> ContainerOpener.open("non-existing.bdoc")
    );

    assertThat(caughtException.getCause(), instanceOf(FileNotFoundException.class));
  }

  @Test
  public void openClosedStreamThrowsException() throws IOException {
    try (FileInputStream stream = new FileInputStream("src/test/resources/testFiles/helper-files/test.txt")) {
      stream.close();

      DigiDoc4JException caughtException = assertThrows(
              DigiDoc4JException.class,
              () -> ContainerOpener.open(stream, false)
      );

      assertThat(caughtException.getCause(), instanceOf(IOException.class));
    }
  }

  @Test
  public void testLargeFileSigning() {
    BDocContainer container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC)
        .withConfiguration(new Configuration(Configuration.Mode.TEST)).build();
    container.getConfiguration().setMaxFileSizeCachedInMemoryInMB(10);
    container.addDataFile(createNonEmptyLargeContainer(container.getConfiguration().getMaxDataFileCachedInBytes() + 100), "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
  }

  @Test
  public void openLargeFileFromStream() throws IOException {
    BDocContainer container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC).
        withConfiguration(new Configuration(Configuration.Mode.TEST)).build();
    container.getConfiguration().setMaxFileSizeCachedInMemoryInMB(0);
    String file = createNonEmptyLargeContainer(container.getConfiguration().getMaxDataFileCachedInBytes() + 100);
    container.addDataFile(file, "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    container.saveAsFile(file);
    try (FileInputStream stream = new FileInputStream(file)) {
      ContainerOpener.open(stream, true);
    }
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void openAddFileFromStream() throws IOException {
    BDocContainer container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.getConfiguration().setMaxFileSizeCachedInMemoryInMB(0);
    String file = createNonEmptyLargeContainer(container.getConfiguration().getMaxDataFileCachedInBytes() + 100);
    try (FileInputStream stream = new FileInputStream(file)) {
      container.addDataFile(stream, "fileName", "text/plain");
      createSignatureBy(container, pkcs12SignatureToken);
      container.saveAsFile(file);
      FileInputStream stream2 = new FileInputStream(file);
      ContainerOpener.open(stream2, true);
      IOUtils.closeQuietly(stream2);
    }
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testGetDocumentType() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    Assert.assertEquals(Constant.BDOC_CONTAINER_TYPE, container.getType());
  }

  @Test
  public void testAddTwoFilesAsStream() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    stream.mark(Integer.MAX_VALUE);
    container.addDataFile(stream, "test1.txt", "text/plain");
    stream.reset();
    container.addDataFile(stream, "test2.txt", "text/plain");
  }

  @Test
  public void testAddTwoFilesAsFileWithoutOCSP() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void testGetFileNameAndID() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Assert.assertEquals("test.xml", container.getDataFiles().get(1).getName());
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getId());
    Assert.assertEquals("test.xml", container.getDataFiles().get(1).getId());
  }

  @Test
  public void testAddTwoFilesAsFileWithOCSP() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getDataFiles().size());
  }

  @Test
  public void saveToStream() throws Exception {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "test_bytes.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    File expectedContainerAsFile = new File(getFileBy("bdoc"));
    try (OutputStream out = Files.newOutputStream(expectedContainerAsFile.toPath())) {
      container.save(out);
    }
    Assert.assertTrue(Files.exists(expectedContainerAsFile.toPath()));
    Container containerToTest = ContainerOpener.open(expectedContainerAsFile.getAbsolutePath());
    Assert.assertArrayEquals(new byte[]{0x42}, containerToTest.getDataFiles().get(0).getBytes());
  }

  @Test
  public void saveExistingContainerToStream() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals(3, container.getSignatures().size());
    InputStream inputStream = container.saveAsStream();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    IOUtils.copy(inputStream, outputStream);
    ByteArrayInputStream savedContainerStream = new ByteArrayInputStream(outputStream.toByteArray());
    container = ContainerOpener.open(savedContainerStream, false);
    Assert.assertEquals(3, container.getSignatures().size());
    Assert.assertEquals(1, container.getDataFiles().size());
  }

  @Test
  public void saveToStreamThrowsException() throws IOException {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    File expectedContainerAsFile = new File(getFileBy("bdoc"));
    try (OutputStream out = Files.newOutputStream(expectedContainerAsFile.toPath())) {
      out.close();

      TechnicalException caughtException = assertThrows(
              TechnicalException.class,
              () -> container.save(out)
      );

      assertThat(caughtException.getMessage(), equalTo("Unable to write Zip entry to asic container"));
    }
  }

  @Test
  public void saveExistingContainer() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    String file = getFileBy("asice");
    container.saveAsFile(file);
    Container savedContainer = ContainerOpener.open(file);
    Assert.assertTrue(savedContainer.validate().isValid());
    Assert.assertEquals(1, savedContainer.getDataFiles().size());
    Assert.assertEquals(2, savedContainer.getSignatures().size());
    try (ZipFile zip = new ZipFile(file)) {
      Assert.assertNotNull(zip.getEntry("mimetype"));
      Assert.assertNotNull(zip.getEntry("test.txt"));
      Assert.assertNotNull(zip.getEntry("META-INF/manifest.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    }
  }

  @Test
  public void containerIsLT() {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
  }

  @Test
  public void signWithoutDataFile() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC, Container.class);

    ContainerWithoutFilesException caughtException = assertThrows(
            ContainerWithoutFilesException.class,
            () -> createSignatureBy(container, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), equalTo("Container does not contain any data files"));
  }

  @Test
  public void nonStandardMimeType() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/newtype");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    SignatureValidationResult result = container.validate();
    Assert.assertEquals(0, result.getErrors().size());
    Assert.assertEquals("text/newtype", container.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void twoStepSigning() throws IOException {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container).
        withSigningCertificate(pkcs12SignatureToken.getCertificate()).buildDataToSign();
    Signature signature = dataToSign.finalize(sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm()));
    container.addSignature(signature);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertTrue(container.validate().isValid());
    Assert.assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignatures().get(0);
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", resultSignature.getSignatureMethod());
    assertThat(resultSignature.getSignerRoles(), empty());
    Assert.assertEquals("", resultSignature.getCity());
    Assert.assertTrue(StringUtils.isNotBlank(resultSignature.getId()));
    Assert.assertNotNull(resultSignature.getOCSPCertificate());
    Assert.assertNotNull(resultSignature.getSigningCertificate());
    Assert.assertNotNull(resultSignature.getAdESSignature());
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
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).withSigningCertificate(pkcs12SignatureToken.getCertificate()).
        withSignatureId("S99").withRoles("manager", "employee").withCity("city").withStateOrProvince("state").
        withPostalCode("postalCode").withCountry("country").buildDataToSign();
    byte[] signatureValue = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
    Signature resultSignature = container.getSignatures().get(0);
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", resultSignature.getSignatureMethod());
    Assert.assertEquals("employee", resultSignature.getSignerRoles().get(1));
    Assert.assertEquals("city", resultSignature.getCity());
    Assert.assertEquals("S99", resultSignature.getId());
  }

  @Test
  public void testContainerCreationAsTSA() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken);
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
  }

  @Test
  public void testBDocTM() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> createSignatureBy(container, SignatureProfile.LT_TM, pkcs12SignatureToken)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create LT_TM signatures"));
  }

  @Test
  public void testBDocTS() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void containerWithBESProfileHasNoValidationErrors() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    Assert.assertEquals(SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertFalse(container.validate().isValid());
  }

  @Test
  public void signWithECCCertificate() {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC);
    Signature signature = SignatureBuilder.aSignature(container)
            .withSignatureToken(pkcs12EccSignatureToken)
            .withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA)
            .invokeSigning();
    container.addSignature(signature);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void zipFileComment() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    String expectedComment = Constant.USER_AGENT_STRING;
    try (ZipFile zipFile = new ZipFile(file)) {
      Assert.assertEquals(expectedComment, zipFile.getEntry("mimetype").getComment());
      Assert.assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
      Assert.assertEquals(expectedComment, zipFile.getEntry("META-INF/manifest.xml").getComment());
      Assert.assertEquals(expectedComment, zipFile.getEntry("META-INF/signatures0.xml").getComment());
      Assert.assertEquals(expectedComment, zipFile.getEntry("test.txt").getComment());
    }
  }

  @Test
  public void signingMoreThanTwoFiles() {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC,
        Paths.get("src/test/resources/testFiles/special-char-files/dds_dds_JÜRIÖÖ € žŠ päev.txt"),
        "text/plain");
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_pakitud.zip", "text/plain");
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_SK.jpg", "text/plain");
    container.addDataFile("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    Signature signature = container.getSignatures().get(0);
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_dds_JÜRIÖÖ € žŠ päev.txt");
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_pakitud.zip");
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_SK.jpg");
    TestAssert.assertSignatureMetadataContainsFileName(signature, "dds_acrobat.pdf");
  }

  @Test
  public void signatureFileNamesShouldBeInSequence() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    createSignatureBy(container, pkcs12SignatureToken);
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    try (ZipFile zip = new ZipFile(file)) {
      Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
    }
  }

  @Test
  public void whenSigningExistingContainer_withTwoSignatures_shouldCreateSignatureFileName_signatures2() throws Exception {
    try (ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc")) {
      Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    }
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    try (ZipFile zip = new ZipFile(file)) {
      Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
    }
  }

  @Test
  public void whenSigningExistingContainer_with_signatures1_xml_shouldCreateSignatureFileName_signatures2() throws Exception {
    try (ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc")) {
      Assert.assertNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    }
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    try (ZipFile zip = new ZipFile(file)) {
      Assert.assertNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures2.xml"));
    }
  }

  @Test
  public void addSignatureWithDuplicateSignatureId_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/test.asice");
    Signature signature = SignatureBuilder.aSignature(container).
            withSignatureToken(pkcs12SignatureToken).withSignatureId("S0").invokeSigning();

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> container.addSignature(signature)
    );

    assertThat(caughtException.getMessage(), equalTo("Signature with Id \"S0\" already exists"));
  }

  @Test
  public void addTimemarkSignatureToAsicEContainer_throwsException() {
    Container bdocContainer = ContainerOpener.open(BDOC_WITH_TM_SIG);
    Signature timemarkSignature = bdocContainer.getSignatures().get(0);
    assertTimemarkSignature(timemarkSignature);

    Container asicEContainer = ContainerOpener.open(ASICE_WITH_TS_SIG);
    assertAsicEContainer(asicEContainer);

    IllegalSignatureProfileException caughtException = assertThrows(
            IllegalSignatureProfileException.class,
            () -> asicEContainer.addSignature(timemarkSignature)
    );

    assertThat(caughtException.getMessage(), equalTo(
            "Cannot add BDoc specific (LT_TM) signature to ASiCE container"
    ));
  }

  @Test
  public void addBEpesSignatureToAsicEContainer_throwsException() {
    Container bdocContainer = ContainerOpener.open(BDOC_WITH_B_EPES_SIG);
    Signature bEpesSignature = bdocContainer.getSignatures().get(0);
    assertBEpesSignature(bEpesSignature);

    Container asicEContainer = ContainerOpener.open(ASICE_WITH_TS_SIG);
    assertAsicEContainer(asicEContainer);

    IllegalSignatureProfileException caughtException = assertThrows(
            IllegalSignatureProfileException.class,
            () -> asicEContainer.addSignature(bEpesSignature)
    );

    assertThat(caughtException.getMessage(), equalTo(
            "Cannot add BDoc specific (B_EPES) signature to ASiCE container"
    ));
  }

  @Test
  public void whenSigningContainer_withSignatureNameContainingNonNumericCharacters_shouldCreateSignatureFileName_inSequence() throws Exception {
    try (ZipFile zip = new ZipFile("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice")) {
      Assert.assertNotNull(zip.getEntry("META-INF/l77Tsignaturesn00B.xml"));
      Assert.assertNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNull(zip.getEntry("META-INF/signatures1.xml"));
    }
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice");
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    try (ZipFile zip = new ZipFile(file)) {
      Assert.assertNotNull(zip.getEntry("META-INF/l77Tsignaturesn00B.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
      Assert.assertNotNull(zip.getEntry("META-INF/signatures1.xml"));
    }
  }

  @Test
  public void whenOpeningContainer_withTwoDataFilesWithSameName_andWithSingleReferenceInManifest_shouldThrowException() {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/KS-19_IB-3721_bdoc21-TM-2fil-samename-1sig3.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST));

    DuplicateDataFileException caughtException = assertThrows(
            DuplicateDataFileException.class,
            containerBuilder::build
    );

    assertThat(caughtException.getMessage(), equalTo("Container contains duplicate data file: readme.txt"));
  }

  @Test
  public void whenOpeningContainer_withTwoManifests_oneIsErroneous_shouldThrowException() {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/KS-10_manifest_topelt_bdoc21_TM.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST));

    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            containerBuilder::build
    );

    assertThat(caughtException.getMessage(), equalTo("Multiple manifest.xml files disallowed"));
  }

  @Test
  public void whenExistingContainer_hasWrongMimeSlash_weShouldNotThrowException() {
    SignatureValidationResult result = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/INC166120_wrong_mime_slash.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST)).build().validate();
    Assert.assertFalse("Container is not invalid", result.isValid());
  }

  @Test
  public void whenOpeningContainer_withSignatureInfo_butNoSignedDataObject_shouldThrowException() {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/3863_bdoc21_TM_no_datafile.bdoc")
        .withConfiguration(new Configuration(Configuration.Mode.TEST));

    ContainerWithoutFilesException caughtException = assertThrows(
            ContainerWithoutFilesException.class,
            containerBuilder::build
    );

    assertThat(caughtException.getMessage(), equalTo("The reference data object(s) is not found!"));
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
  public void containerWithImplicitPolicy(){
    Container container = ContainerOpener.open
        ("src/test/resources/testFiles/valid-containers/validTSwImplicitPolicy.asice");
    ContainerValidationResult validate = container.validate();
    Assert.assertTrue(validate.isValid());
  }

  @Test
  public void bdocTM_OcspResponderCert_shouldContainResponderCertIdAttribute() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    BDocSignature signature = (BDocSignature) container.getSignatures().get(0);
    Assert.assertEquals(1, countOCSPResponderCertificates(signature.getOrigin().getDssSignature()));
  }

  @Test
  public void savingContainerWithoutSignatures_shouldNotThrowException() throws Exception {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Assert.assertTrue(container.getSignatures().isEmpty());
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertTrue(container.validate().isValid());
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    Container savedContainer = ContainerOpener.open(file);
    Assert.assertTrue(savedContainer.getSignatures().isEmpty());
    Assert.assertEquals(1, container.getDataFiles().size());
    byte[] expectedDataFileBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] actualDataFileBytes = savedContainer.getDataFiles().get(0).getBytes();
    Assert.assertArrayEquals(expectedDataFileBytes, actualDataFileBytes);
  }

  @Test
  public void openBDoc_withoutCAConfiguration_shouldNotThrowException() {
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", configuration);
    assertThat(container, Matchers.instanceOf(BDocContainer.class));
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void timeStampCertStatusDeprecated() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/invalid-containers/invalid-containers-23816_leedu_live_TS_authority.asice",
            new Configuration(Configuration.Mode.PROD)
    );
    Assert.assertFalse(container.validate().isValid());
  }

  @Test
  public void containerWithSignaturePolicyByDefault() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    BDocSignature bdocSignature = (BDocSignature) container.getSignatures().get(0);
    SignaturePolicy policyId = bdocSignature.getOrigin().getDssSignature().getSignaturePolicy();
    Assert.assertEquals("https://www.sk.ee/repository/bdoc-spec21.pdf", policyId.getUri());
    Assert.assertEquals("1.3.6.1.4.1.10015.1000.3.2.1", policyId.getIdentifier());
    Assert.assertEquals(eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256, policyId.getDigest().getAlgorithm());
    Assert.assertArrayEquals(Base64.decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="), policyId.getDigest().getValue());
  }

  @Test
  public void containerWithMultipleIdenticallyNamedSignaturesShouldFail() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/KS-15_signatures_xml_topelt.bdoc");
    Assert.assertSame(2, container.getSignatures().size());

    ContainerValidationResult validationResult = container.validate();
    Assert.assertFalse(validationResult.isValid());

    Assert.assertSame(1, validationResult.getContainerErrors().size());
    Assert.assertEquals(validationResult.getContainerErrors().get(0).getMessage(), "Duplicate signature files: META-INF/signatures1.xml");

    Assert.assertSame(4, validationResult.getWarnings().size());

    Assert.assertSame(11, validationResult.getErrors().size());
    List<DigiDoc4JException> errors = validationResult.getErrors();
    Assert.assertEquals(errors.get(0).getMessage(), "Wrong policy identifier: 1.3.6.1.4.1.10015.1000.3.1.1");
    Assert.assertEquals(errors.get(1).getMessage(), "The signature policy is not available!");
    Assert.assertEquals(errors.get(2).getMessage(), "The certificate validation is not conclusive!");
    Assert.assertEquals(errors.get(3).getMessage(), "The current time is not in the validity range of the signer's certificate!");
    Assert.assertEquals(errors.get(4).getMessage(), "OCSP nonce is invalid");
    Assert.assertEquals(errors.get(5).getMessage(), "Wrong policy identifier: 1.3.6.1.4.1.10015.1000.3.1.1");
    Assert.assertEquals(errors.get(6).getMessage(), "The signature policy is not available!");
    Assert.assertEquals(errors.get(7).getMessage(), "The certificate validation is not conclusive!");
    Assert.assertEquals(errors.get(8).getMessage(), "The current time is not in the validity range of the signer's certificate!");
    Assert.assertEquals(errors.get(9).getMessage(), "OCSP nonce is invalid");

    DigiDoc4JException duplicateSigFileEx = errors.get(10);
    Assert.assertTrue(duplicateSigFileEx instanceof DuplicateSignatureFilesException);
    Assert.assertEquals(duplicateSigFileEx.getMessage(), "Duplicate signature files: META-INF/signatures1.xml");
  }

  /*
   * RESTRICTED METHODS
   */

  private int countOCSPResponderCertificates(XAdESSignature signature) {
    return countResponderCertIdInsCertificateValues(DomUtils.getElement(signature.getSignatureElement(),
            signature.getXAdESPaths().getCertificateValuesPath()));
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