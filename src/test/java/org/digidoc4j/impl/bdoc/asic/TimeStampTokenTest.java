package org.digidoc4j.impl.bdoc.asic;

import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.asic.TimeStampValidationResult;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.SystemOutRule;
import org.junit.rules.TemporaryFolder;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * Created by Andrei on 22.11.2017.
 */
public class TimeStampTokenTest extends DigiDoc4JTestHelper {

  public static final String META_INF_TIMESTAMP_TST = "META-INF/timestamp.tst";
  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Rule
  public final SystemOutRule sout = new SystemOutRule().enableLog();

  @After
  public void cleanUp() {
    testFolder.delete();
  }

  @Test
  public void testCreateTimeStampContainer(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        withConfiguration(configuration).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").
        withTimeStampToken(DigestAlgorithm.SHA256).
        build();

    container.saveAsFile("src\\test\\resources\\testFiles\\tmp\\newTestTimestamp.asics");

    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());
  }

  @Test
  public void testOpenTimeStampContainer(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile("src\\test\\resources\\testFiles\\valid-containers\\testtimestamp.asics").
        build();

    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());
  }

  @Test
  public void testOpenValidTimeStampContainer(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile("src\\test\\resources\\testFiles\\valid-containers\\timestamptoken-ddoc.asics").
        build();

    TimeStampValidationResult validate = (TimeStampValidationResult) container.validate();
    Assert.assertEquals("SK TIMESTAMPING AUTHORITY", validate.getSignedBy());
    Assert.assertEquals(Indication.TOTAL_PASSED, validate.getIndication());
    assertTrue(validate.isValid());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenContainerTwoDataFiles(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile("src\\test\\resources\\testFiles\\invalid-containers\\timestamptoken-two-data-files.asics").
        build();

    ValidationResult validate = container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidTimeStampContainer(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile("src\\test\\resources\\testFiles\\invalid-containers\\timestamptoken-invalid.asics").
        build();

    ValidationResult validate = container.validate();
  }

  @Test
  public void generatedTimestampToken() throws Exception {
    try (FileInputStream fis = new FileInputStream("src\\test\\resources\\testFiles\\tst\\timestamp.tst")) {
      TimestampToken token = new TimestampToken(Utils.toByteArray(fis), TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
      assertNotNull(token);
      assertNotNull(token.getGenerationTime());
      assertTrue(Utils.isCollectionNotEmpty(token.getCertificates()));
      assertNotNull(token.getSignatureAlgorithm());
      assertEquals(TimestampType.ARCHIVE_TIMESTAMP, token.getTimeStampType());
      assertEquals(DigestAlgorithm.SHA256, token.getSignedDataDigestAlgo());
      assertEquals(SignatureAlgorithm.RSA_SHA256, token.getSignatureAlgorithm());
      assertTrue(Utils.isStringNotBlank(token.getEncodedSignedDataDigestValue()));

      assertNotNull(token.getIssuerToken());
      assertTrue(token.isSignedBy(token.getIssuerToken()));
      assertFalse(token.isSelfSigned());

      assertFalse(token.matchData(new byte[] { 1, 2, 3 }));
      assertTrue(token.isMessageImprintDataFound());
      assertFalse(token.isMessageImprintDataIntact());

      assertTrue(token.isMessageImprintDataFound());
    }
  }

  @Test
  public void createsContainerWithTstASICS() throws Exception {
    String fileName = testFolder.getRoot().getPath() + "\\testTst.asics";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};

    callMainWithoutSystemExit(params);

    ZipFile zipFile = new ZipFile(fileName);
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);
    ZipEntry timestampEntry = zipFile.getEntry(META_INF_TIMESTAMP_TST);

    assertNotNull(mimeTypeEntry);
    assertNotNull(manifestEntry);
    assertNotNull(timestampEntry);

    String mimeTypeContent = getTxtFiles(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeType.ASICS.getMimeTypeString()));
    String manifestContent = getTxtFiles(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeType.ASICS.getMimeTypeString()));

    Container container = ContainerOpener.open(fileName);
    ValidationResult validate = container.validate();
    System.out.println(validate.getErrors());
    assertTrue(validate.isValid());

    assertEquals("ASICS", container.getType());
  }

  @Test
  public void tstASICSAddTwoSignatures() throws Exception {
    String fileName = testFolder.getRoot().getPath() + "\\testTst.asics";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};

    callMainWithoutSystemExit(params);

    String[] params2 = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain", "-datst", "SHA256", "-tst"};

    callMainWithoutSystemExit(params2);
    assertThat(sout.getLog(),containsString(
        "This container has already timestamp. Should be no signatures in case of timestamped ASiCS container."));

  }

  @Test
  public void tstASICSAddTwoFiles() throws Exception {
    String fileName = testFolder.getRoot().getPath() + "\\testTst.asics";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};

    callMainWithoutSystemExit(params);

    String[] params2 = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain"};

    callMainWithoutSystemExit(params2);
    assertThat(sout.getLog(),containsString(
        "This container has already timestamp. Should be no signatures in case of timestamped ASiCS container."));
  }

  @Test
  public void tstASICSAddPKCS12Signature() throws Exception {
    String fileName = testFolder.getRoot().getPath() + "\\testTst.asics";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};

    callMainWithoutSystemExit(params);

    String[] params2 = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params2);
    assertThat(sout.getLog(),containsString(
        "This container has already timestamp. Should be no signatures in case of timestamped ASiCS container."));

  }

  @Test
  public void tstASICSAddPKCS12SignatureFirst() throws Exception {
    String fileName = testFolder.getRoot().getPath() + "\\testTst.asics";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params2 = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params2);

    String[] params = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};

    callMainWithoutSystemExit(params);

    assertThat(sout.getLog(),containsString(
        "Datafiles cannot be added to an already signed container"));

  }
}