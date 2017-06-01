/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.digidoc4j.impl.bdoc.BDocContainer;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.utils.Helper;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import org.xml.sax.SAXException;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import static org.apache.commons.codec.binary.Base64.encodeBase64String;
import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;
import static org.digidoc4j.Configuration.Mode.TEST;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;
import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

public class ContainerTest extends DigiDoc4JTestHelper {
  public static final String TEXT_MIME_TYPE = "text/plain";

  public static final String CERTIFICATE =
      "MIIFEzCCA/ugAwIBAgIQSXxaK/qTYahTT77Z9I56EjANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaX" +
          "RzZWVyaW1pc2tlc2t1czEfMB0GA1UEAwwWVEVTVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTE0" +
          "MDQxNzExNDUyOVoXDTE2MDQxMjIwNTk1OVowgbQxCzAJBgNVBAYTAkVFMQ8wDQYDVQQKDAZFU1RFSUQxGjAYBgNVBAsMEWRpZ2l0YWwgc2" +
          "lnbmF0dXJlMTEwLwYDVQQDDCjFvcOVUklOw5xXxaBLWSxNw4RSw5wtTMOWw5ZaLDExNDA0MTc2ODY1MRcwFQYDVQQEDA7FvcOVUklOw5xX" +
          "xaBLWTEWMBQGA1UEKgwNTcOEUsOcLUzDlsOWWjEUMBIGA1UEBRMLMTE0MDQxNzY4NjUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAo" +
          "IBAQChn9qVaA+x3RkDBrD5ujwfnreK5/Nb+Nvo9Vg5OLMn3JKUoUhFX6A/q5lBUylK/CU/lNRTv/kicqnu1aCyAiW0XVYk8jrOI1wRbHey" +
          "BMq/5gVm/vbbRtMi/XGLkgMZ5UDxY0QZfmu8wlRJ8164zRNocuUJLLXWOB6vda2RRXC3Cix4TDvQwGmPrQQJ8dzDIJEkLS7NCLBTcndm7b" +
          "uQegRc043gKMjUmRhGZEzF4oJa4pMfXqeSa+PUtrNyNNNQaOwTH29R8aFfGU2xorVvxoUieNipyWMEz8BTUGwwIceapWi77loBV/VQfStX" +
          "nQNu/s6BC04ss43O6sK70MB1qlRZAgMBAAGjggFmMIIBYjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDCBmQYDVR0gBIGRMIGOMIGLBg" +
          "orBgEEAc4fAwEBMH0wWAYIKwYBBQUHAgIwTB5KAEEAaQBuAHUAbAB0ACAAdABlAHMAdABpAG0AaQBzAGUAawBzAC4AIABPAG4AbAB5ACAA" +
          "ZgBvAHIAIAB0AGUAcwB0AGkAbgBnAC4wIQYIKwYBBQUHAgEWFWh0dHA6Ly93d3cuc2suZWUvY3BzLzAdBgNVHQ4EFgQUEjVsOkaNOGG0Gl" +
          "cF4icqxL0u4YcwIgYIKwYBBQUHAQMEFjAUMAgGBgQAjkYBATAIBgYEAI5GAQQwHwYDVR0jBBgwFoAUQbb+xbGxtFMTjPr6YtA0bW0iNAow" +
          "RQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL3d3dy5zay5lZS9yZXBvc2l0b3J5L2NybHMvdGVzdF9lc3RlaWQyMDExLmNybDANBgkqhkiG9w" +
          "0BAQUFAAOCAQEAYTJLbScA3+Xh/s29Qoc0cLjXW3SVkFP/U71/CCIBQ0ygmCAXiQIp/7X7JonY4aDz5uTmq742zZgq5FA3c3b4NtRzoiJX" +
          "FUWQWZOPE6Ep4Y07Lpbn04sypRKbVEN9TZwDy3elVq84BcX/7oQYliTgj5EaUvpe7MIvkK4DWwrk2ffx9GRW+qQzzjn+OLhFJbT/QWi81Q" +
          "2CrX34GmYGrDTC/thqr5WoPELKRg6a0v3mvOCVtfIxJx7NKK4B6PGhuTl83hGzTc+Wwbaxwjqzl/SUwCNd2R8GV8EkhYH8Kay3Ac7Qx3ag" +
          "rJJ6H8j+h+nCKLjIdYImvnznKyR0N2CRc/zQ+g==";

  private PKCS12SignatureToken PKCS12_SIGNER;

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  File tempFile;


  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12SignatureToken("testFiles/p12/signout.p12", "test".toCharArray());
    tempFile = testFolder.newFile("tempFile.txt");
  }

  @AfterClass
  public static void deleteTemporaryFiles() {
    try {
      DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("."));
      for (Path item : directoryStream) {
        String fileName = item.getFileName().toString();
        if ((fileName.endsWith("bdoc") || fileName.endsWith("ddoc")) && fileName.startsWith("test"))
          Files.deleteIfExists(item);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void createBDocContainersByDefault() {
    assertTrue(createContainer() instanceof BDocContainer);
  }

  @Test
  public void createBDocContainer() {
    assertTrue(createBDoc() instanceof BDocContainer);
  }

  private Container createBDoc() {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        build();
    return container;
  }

  @Test
  public void createDDocContainer() {
    assertTrue(createDDoc() instanceof DDocContainer);
  }

  @Test
  public void openBDocContainerWhenTheFileIsAZipAndTheExtensionIsBDoc() {
    assertTrue(ContainerOpener.open("testFiles/invalid-containers/zip_file_without_asics_extension.bdoc") instanceof BDocContainer);
  }

  @Test
  public void openDDocContainerForAllOtherFiles() {
    assertTrue(ContainerOpener.open("testFiles/invalid-containers/changed_digidoc_test.ddoc") instanceof DDocContainer);
  }

  @Test
  public void testAddOneFileToContainerForBDoc() throws Exception {
    Container container = createContainer();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    List<DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getName());
    assertEquals(TEXT_MIME_TYPE, dataFiles.get(0).getMediaType());
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExistsForBDoc() throws Exception {
    Container bDocContainer = createContainer();
    bDocContainer.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    bDocContainer.removeDataFile("test.txt");
    assertEquals(0, bDocContainer.getDataFiles().size());
  }

  @Test
  public void testCreateBDocContainerSpecifiedByDocumentTypeForBDoc() throws Exception {
    Container asicContainer = createBDoc();
    asicContainer.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    TestDataBuilder.signContainer(asicContainer);
    asicContainer.save("test.bdoc");
    assertTrue(Helper.isZipFile(new File("test.bdoc")));
  }

  @Test
  public void testCreateDDocContainer() throws Exception {
    Container dDocContainer = createDDoc();
    dDocContainer.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    dDocContainer.sign(PKCS12_SIGNER);
    dDocContainer.save("testCreateDDocContainer.ddoc");

    assertTrue(Helper.isXMLFile(new File("testCreateDDocContainer.ddoc")));
  }

  @Test
  public void testAddOneFileToContainerForDDoc() throws Exception {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    List<DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getName());
    assertEquals(TEXT_MIME_TYPE, dataFiles.get(0).getMediaType());
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExistsForDDoc() throws Exception {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    container.save("testRemovesOneFileFromContainerWhenFileExistsFor.ddoc");

    Container container1 = ContainerOpener.open("testRemovesOneFileFromContainerWhenFileExistsFor.ddoc");
    container1.removeDataFile("testFiles/helper-files/test.txt");
    assertEquals(0, container1.getDataFiles().size());
  }

  @Test
  public void addLargeFileToBDoc() throws Exception {
    DataFile dataFile = new LargeDataFile(new ByteArrayInputStream(new byte[]{0, 1, 2, 3}), "large-doc.txt", TEXT_MIME_TYPE);
    Container container = createBDoc();
    container.addDataFile(dataFile);
    assertEquals(1, container.getDataFiles().size());
    container.saveAsFile(tempFile.getPath());
    container = ContainerOpener.open(tempFile.getPath());
    assertEquals(1, container.getDataFiles().size());
    assertEquals("large-doc.txt", container.getDataFiles().get(0).getName());
  }

  @Test
  public void addLargeFileToDDoc() throws Exception {
    DataFile dataFile = new DataFile(new ByteArrayInputStream(new byte[]{0, 1, 2, 3}), "large-doc.txt", TEXT_MIME_TYPE);
    Container container = createDDoc();
    container.addDataFile(dataFile);
    container.sign(PKCS12_SIGNER);
    assertEquals(1, container.getDataFiles().size());
    assertEquals("large-doc.txt", container.getDataFiles().get(0).getName());
    container.saveAsFile(tempFile.getPath());
  }

  @Test
  public void testOpenCreatedDDocFile() throws Exception {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    container.save("testOpenCreatedDDocFile.ddoc");
    Container containerForReading = ContainerOpener.open("testOpenCreatedDDocFile.ddoc");
    assertEquals(DDOC, containerForReading.getDocumentType());

    assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidFileReturnsError() {
    ContainerOpener.open("testFiles/helper-files/test.txt");
  }

  @Test
  public void testValidateDDoc() throws Exception {
    Container dDocContainer = ContainerOpener.open("testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertFalse(dDocContainer.validate().hasErrors());
    assertFalse(dDocContainer.validate().hasWarnings());
  }

  @Test
  public void openDDocContainerFromFile() throws Exception {
    Container container = ContainerBuilder.
        aContainer("DDOC").
        fromExistingFile("testFiles/valid-containers/ddoc_wo_x509IssueName_xmlns.ddoc").
        build();
    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());
    assertEquals(0, validate.getErrors().size());
    assertTrue(validate.getReport().contains("X509IssuerName has none or invalid namespace: null"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenNotExistingFileThrowsException() {
    ContainerOpener.open("noFile.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenEmptyFileThrowsException() {
    ContainerOpener.open("testFiles/invalid-containers/emptyFile.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testFileTooShortToVerifyIfItIsZipFileThrowsException() {
    ContainerOpener.open("testFiles/invalid-containers/tooShortToVerifyIfIsZip.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenFromStreamTooShortToVerifyIfIsZip() {
    try {
      FileInputStream stream = new FileInputStream(new File("testFiles/invalid-containers/tooShortToVerifyIfIsZip.ddoc"));
      ContainerOpener.open(stream, true);
      IOUtils.closeQuietly(stream);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testAddFileFromStreamToDDoc() throws IOException {
    Container container = createDDoc();
    try (ByteArrayInputStream is = new ByteArrayInputStream(new byte[]{0x42})) {
      container.addDataFile(is, "testFromStream.txt", TEXT_MIME_TYPE);
    }
    DataFile dataFile = container.getDataFiles().get(0);

    assertEquals("testFromStream.txt", dataFile.getName());
  }

  @Test
  public void openContainerFromStreamAsBDoc() throws IOException {
    Container container = createContainer();
    container.addDataFile("testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);
    String containerPath = testFolder.newFile().getPath();
    container.save(containerPath);

    FileInputStream stream = new FileInputStream(containerPath);
    Container containerToTest = ContainerOpener.open(stream, false);
    stream.close();

    assertEquals(1, containerToTest.getSignatures().size());
  }

  @Test
  public void openContainerFromStreamAsDDoc() throws IOException {
    FileInputStream stream = new FileInputStream("testFiles/valid-containers/ddoc_for_testing.ddoc");
    Container container = ContainerOpener.open(stream, false);
    stream.close();

    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testGetSignatureFromDDoc() {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    List<Signature> signatures = container.getSignatures();

    assertEquals(1, signatures.size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddRawSignatureThrowsException() {
    Container container = createDDoc();
    container.addRawSignature(new byte[]{0x42});
  }

  @Test
  public void testAddRawSignatureAsByteArrayForDDoc() throws CertificateEncodingException, IOException, SAXException {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File(("testFiles/xades/test-bdoc-tm.xml")));
    container.addRawSignature(signatureBytes);

    assertEquals(2, container.getSignatures().size());
    assertEquals(CERTIFICATE.replaceAll("\\s", ""), encodeBase64String(getSigningCertificateAsBytes(container, 1)));
    assertXMLEqual(new String(signatureBytes).trim(), new String(container.getSignatures().get(1).getAdESSignature()));
  }

  @Test
  public void throwsErrorWhenCreatesDDOCContainerWithConfiguration() throws Exception {
    Container container = ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        withConfiguration(Configuration.getInstance()).
        build();

    assertEquals("DDOC", container.getType());
  }

  @Test
  public void testExtendToForBDOC() {
    Container container = createContainer();
    container.addDataFile("testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureProfile(B_BES).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);

    container.extendTo(LT);

    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void testExtendToForDDOC() {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", "text/plain");
    container.setSignatureProfile(B_BES);
    container.sign(PKCS12_SIGNER);

    container.extendTo(SignatureProfile.LT_TM);

    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void addRawSignatureToBDocContainer() throws Exception {
    Container container = createBDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("testFiles/xades/valid-bdoc-tm.xml"));
    container.addRawSignature(signatureBytes);
    String containerPath = testFolder.newFile("test-container.bdoc").getPath();
    container.saveAsFile(containerPath);
    container = ContainerOpener.open(containerPath);
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void addRawSignatureToExistingBDocContainer() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile("testFiles/helper-files/test.txt");
    TestDataBuilder.signContainer(container);
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("testFiles/xades/valid-bdoc-tm.xml"));
    container.addRawSignature(signatureBytes);
    String containerPath = testFolder.newFile("test-container.bdoc").getPath();
    container.saveAsFile(containerPath);
    container = ContainerOpener.open(containerPath);
    assertEquals(2, container.getSignatures().size());
    assertTrue(container.validate().isValid());
  }

  @Test(expected = InvalidSignatureException.class)
  public void testAddRawSignatureAsByteArrayForBDoc() throws CertificateEncodingException, IOException, SAXException {
    Container container = createBDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    TestDataBuilder.signContainer(container);
    container.addRawSignature(Base64.decodeBase64("fo4aA1PVI//1agzBm2Vcxj7sk9pYQJt+9a7xLFSkfF10RocvGjVPBI65RMqyxGIsje" +
        "LoeDERfTcjHdNojoK/gEdKtme4z6kvkZzjMjDuJu7krK/3DHBtW3XZleIaWZSWySahUiPNNIuk5ykACUolh+K/UK2aWL3Nh64EWvC8aznLV0" +
        "M21s7GwTv7+iVXhR/6c3O22saWKWsteGT0/AqfcBRoj13H/NyuZOULqU0PFOhbJtV8RyZgC9n2uYBFsnutt5GPvhP+U93gkmFQ0+iC1a9Ktt" +
        "j4QH5si35YmRIe0fp8tGDo6li63/tybb+kQ96AIaRe1NxpkKVDBGNi+VNVNA=="));
  }

  @Test
  public void testAddRawSignatureAsStreamArray() throws CertificateEncodingException, IOException {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    FileInputStream fileInputStream = new FileInputStream("testFiles/xades/test-bdoc-tm.xml");
    container.addRawSignature(fileInputStream);

    assertEquals(1, container.getSignatures().size());
    assertEquals(CERTIFICATE.replaceAll("\\s", ""), encodeBase64String(getSigningCertificateAsBytes(container, 0)));
  }

  private byte[] getSigningCertificateAsBytes(Container container, int index) throws CertificateEncodingException {
    Signature signature = container.getSignatures().get(index);
    return signature.getSigningCertificate().getX509Certificate().getEncoded();
  }

  @Test
  @Ignore("jDigidoc fails to save a container after a raw signature has been added")
  public void testRemoveSignature() throws IOException {
    Container container = createDDoc();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    FileInputStream fileInputStream = new FileInputStream("testFiles/xades/test-bdoc-tm.xml");
    container.addRawSignature(fileInputStream);
    container.save("testRemoveSignature.ddoc");

    Container containerToRemoveSignature = ContainerOpener.open("testRemoveSignature.ddoc");
    containerToRemoveSignature.removeSignature(1);

    assertEquals(1, containerToRemoveSignature.getSignatures().size());
    //todo check is correct signatureXML removed by signing time?
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNotExistingSignatureThrowsException() {
    Container container = createDDoc();
    container.removeSignature(0);
  }


  @Test
  public void testSigningWithSignerInfo() throws Exception {
    Container container = createContainer();
    container.addDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE);
    Signature signature = SignatureBuilder.
        aSignature(container).
        withCity("myCity").
        withStateOrProvince("myStateOrProvince").
        withPostalCode("myPostalCode").
        withCountry("myCountry").
        withRoles("myRole / myResolution").
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);

    assertEquals("myCity", signature.getCity());
    assertEquals("myStateOrProvince", signature.getStateOrProvince());
    assertEquals("myPostalCode", signature.getPostalCode());
    assertEquals("myCountry", signature.getCountryName());
    assertEquals(1, signature.getSignerRoles().size());
    assertEquals("myRole / myResolution", signature.getSignerRoles().get(0));
  }

  @Test(expected = TslCertificateSourceInitializationException.class)
  public void testSetConfigurationForBDoc() throws Exception {
    Configuration conf = new Configuration(TEST);
    conf.setTslLocation("pole");
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(conf).
        withDataFile("testFiles/helper-files/test.txt", TEXT_MIME_TYPE).
        build();
    SignatureBuilder.
        aSignature(container).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
  }

  @Test
  public void mustBePossibleToCreateAndVerifyContainerWhereDigestAlgorithmIsSHA224() throws Exception {
    Container container = createContainer();
    container.addDataFile("testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);

    String containerPath = testFolder.newFile().getPath();
    container.saveAsFile(containerPath);
    container = ContainerOpener.open(containerPath);

    assertEquals("http://www.w3.org/2001/04/xmldsig-more#sha224", container.getSignature(0).getSignatureMethod());
  }

  @Test
  public void constructorWithConfigurationParameter() throws Exception {
    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(Configuration.getInstance()).
        build();
    assertEquals("BDOC", container.getType());
  }

  @Test
  @Ignore // Fails on Jenkins - need to verify
  public void createContainerWhenAttachmentNameContainsEstonianCharacters() throws Exception {
    Container container = createContainer();
    String s = "testFiles/test_o\u0303a\u0308o\u0308u\u0308.txt";
    container.addDataFile(s, "text/plain");
    container.sign(PKCS12_SIGNER);
    assertEquals(1, container.getDataFiles().size());
    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());
  }

  @Test
  public void containerTypeStringValueForBDOC() throws Exception {
    assertEquals("application/vnd.etsi.asic-e+zip", createContainer().getDocumentType().toString());
  }

  @Test
  public void containerTypeStringValueForDDOC() throws Exception {
    assertEquals("DDOC", createDDoc().getDocumentType().toString());
  }

  @Test
  public void testSigningMultipleFilesInContainer() throws Exception {
    Container container = createContainer();
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "1.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "2.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "3.txt", "text/plain");
    TestDataBuilder.signContainer(container);
    container.save(tempFile.getPath());
    assertEquals(3, container.getDataFiles().size());
    assertContainsDataFile("1.txt", container);
    assertContainsDataFile("2.txt", container);
    assertContainsDataFile("3.txt", container);
    Container openedContainer = ContainerOpener.open(tempFile.getPath());
    assertEquals(3, openedContainer.getDataFiles().size());
    assertContainsDataFile("1.txt", openedContainer);
    assertContainsDataFile("2.txt", openedContainer);
    assertContainsDataFile("3.txt", openedContainer);
  }

  private void assertContainsDataFile(String fileName, Container container) {
    for (DataFile file : container.getDataFiles()) {
      if (StringUtils.equals(fileName, file.getName())) {
        return;
      }
    }
    assertFalse("Data file '" + fileName + "' was not found in the container", true);
  }

  private Container createContainer() {
    return ContainerBuilder.aContainer().build();
  }

  private DDocContainer createDDoc() {
    Container container = ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        build();
    return (DDocContainer) container;
  }
}
