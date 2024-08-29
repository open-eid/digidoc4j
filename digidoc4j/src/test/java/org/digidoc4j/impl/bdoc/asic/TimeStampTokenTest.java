/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.asic;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.AsicCompositeContainerValidationResult;
import org.digidoc4j.impl.asic.TimeStampContainerValidationResult;
import org.digidoc4j.impl.asic.asics.AsicSContainerTimestamp;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestSigningUtil;
import org.hamcrest.core.StringContains;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.SystemOutRule;

import java.io.FileInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.digidoc4j.main.TestDigiDoc4JUtil.invokeDigiDoc4jAndReturnExitStatus;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Created by Andrei on 22.11.2017.
 */

public class TimeStampTokenTest extends AbstractTest {

  public static final String META_INF_TIMESTAMP_TST = "META-INF/timestamp.tst";

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test
  public void buildTimestampedContainer_ReadFromFile_ValidationSuccess() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(this.configuration).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").
        withTimeStampToken(DigestAlgorithm.SHA256).build();
    container.saveAsFile(this.getFileBy("asics"));
    TestAssert.assertContainerIsValid(container);
    assertNotNull(container.getTimeStampToken());
  }

  @Test
  public void buildTimestampedContainer_ReadFromFile_ValidAndHasTimestampToken() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/testtimestamp.asics").build();
    TestAssert.assertContainerIsValid(container);
    assertNotNull(container.getTimeStampToken());
    assertEquals(2001, container.getTimeStampToken().getBytes().length);
  }

  @Test
  public void buildTimestampedContainer_TimeStampWithdrawn_ValidationFails() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/timestamptoken-ddoc.asics").build();
    AsicCompositeContainerValidationResult validationResult = (AsicCompositeContainerValidationResult) container.validate();
    TimeStampContainerValidationResult timestampValidationResult = (TimeStampContainerValidationResult) validationResult.getNestingContainerValidationResult();
    Assert.assertEquals("SK TIMESTAMPING AUTHORITY", timestampValidationResult.getSignedBy());
    Assert.assertEquals(Indication.TOTAL_FAILED, timestampValidationResult.getIndication());
    TestAssert.assertContainerIsInvalid(validationResult);
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "The certificate is not related to a granted status at time-stamp lowest POE time!");
  }

  @Test
  public void buildTimestampedContainer_ContainerHasValidTimeStamp_ValidationSuccess() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(configuration).
            fromExistingFile("src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics").build();
    TimeStampContainerValidationResult validate = (TimeStampContainerValidationResult) container.validate();
    Assert.assertEquals("DEMO SK TIMESTAMPING AUTHORITY 2023E", validate.getSignedBy());
    Assert.assertEquals(Indication.TOTAL_PASSED, validate.getIndication());
    TestAssert.assertContainerIsValid(validate);
  }

  @Ignore("TODO: DD4J-1083")
  @Test(expected = DigiDoc4JException.class)
  public void testOpenContainerTwoDataFiles() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/invalid-containers/timestamptoken-two-data-files.asics").build();
    container.validate();
  }

  @Ignore("TODO: DD4J-1083")
  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidTimeStampContainer() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/invalid-containers/timestamptoken-invalid.asics").build();
    container.validate();
  }

  @Test
  public void constructTimestampToken_SetTypeAsArchiveTimestamp_ValidationSuccess() throws Exception {
    try (FileInputStream fis = new FileInputStream("src/test/resources/testFiles/tst/timestamp.tst")) {
      TimestampToken token = new TimestampToken(Utils.toByteArray(fis), TimestampType.ARCHIVE_TIMESTAMP);
      assertNotNull(token);
      assertNotNull(token.getGenerationTime());
      Assert.assertTrue(Utils.isCollectionNotEmpty(token.getCertificates()));
      assertNull(token.getSignatureAlgorithm());
      Assert.assertTrue(token.isSignedBy(token.getCertificates().get(0)));
      assertNotNull(token.getSignatureAlgorithm());
      Assert.assertEquals(TimestampType.ARCHIVE_TIMESTAMP, token.getTimeStampType());
      Assert.assertEquals(DigestAlgorithm.SHA256, token.getMessageImprint().getAlgorithm());
      Assert.assertEquals(SignatureAlgorithm.RSA_SHA512, token.getSignatureAlgorithm());
      Assert.assertTrue(Utils.isStringNotBlank(Utils.toBase64(token.getMessageImprint().getValue())));
      Assert.assertFalse(token.isSelfSigned());
      Assert.assertFalse(token.matchData(new byte[]{1, 2, 3}));
      Assert.assertTrue(token.isMessageImprintDataFound());
      Assert.assertFalse(token.isMessageImprintDataIntact());
      Assert.assertTrue(token.isMessageImprintDataFound());
    }
  }

  @Test
  public void createASICSContainerWithTst_AddOneDataFile_ValidationSuccess() throws Exception {
    String fileName = this.getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    ZipFile zipFile = new ZipFile(fileName);
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);
    ZipEntry timestampEntry = zipFile.getEntry(META_INF_TIMESTAMP_TST);
    assertNotNull(mimeTypeEntry);
    assertNotNull(manifestEntry);
    assertNotNull(timestampEntry);
    String mimeTypeContent = this.getFileContent(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeTypeEnum.ASICS.getMimeTypeString()));
    String manifestContent = this.getFileContent(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeTypeEnum.ASICS.getMimeTypeString()));
    Container container = ContainerOpener.open(fileName);
    SignatureValidationResult validate = container.validate();
    Assert.assertTrue(validate.isValid());
    Assert.assertEquals("ASICS", container.getType());
  }

  @Test
  public void createASICSContainerWithTst_AddDataFileAndTimestampTwice_Error() {
    String fileName = this.getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);

    parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain", "-datst", "SHA256", "-tst"};
    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(this.stdOut.getLog(), StringContains.containsString(
        "Datafiles cannot be added to an already timestamped container"));
  }

  @Test
  public void createASICSContainerWithTst_AddDataFileTwice_Error() {
    String fileName = this.getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);

    parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain"};
    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(this.stdOut.getLog(), StringContains.containsString(
        "Datafiles cannot be added to an already timestamped container"));
  }

  @Test
  public void createASICSContainerWithTst_AddTimestampTwice_Success() {
    String fileName = this.getFileBy("asics");
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tst");
    assertEquals(0, caughtExitStatus);

    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-tst");
    assertEquals(0, caughtExitStatus);

    Container container = ContainerOpener.open(fileName);
    Assert.assertTrue(container.validate().isValid());
    Assert.assertEquals(2, container.getTimestamps().size());
    Assert.assertEquals("ASICS", container.getType());
  }

  @Test
  public void createASICSContainerWithTst_SpecifyCustomTspSource_SpecifiedTspUsed() {
    String fileName = this.getFileBy("asics");
    String tspSource = "http://tsa.demo.sk.ee/tsarsa";

    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tspsource", tspSource, "-tst");

    assertEquals(0, caughtExitStatus);
    assertThat(this.stdOut.getLog(), StringContains.containsString("Using TSP Source " + tspSource));
    Container container = ContainerOpener.open(fileName);
    Assert.assertTrue(container.validate().isValid());
    Assert.assertEquals(1, container.getTimestamps().size());
  }

  @Test
  public void createASICSContainerWithTst_SpecifyCustomNonRoutableTspSource_ErrorCallingTSP() {
    String fileName = this.getFileBy("asics");
    String tspSource = "http://10.255.255.1/";

    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tspsource", tspSource, "-tst");

    assertEquals(1, caughtExitStatus);
    assertThat(this.stdOut.getLog(), StringContains.containsString(String.format("Unable to process <TSP> POST call for service <%s>", tspSource)));
  }

  @Test
  public void createASICSContainerWithTst_SpecifyDigestAlgo_SpecifiedDigestAlgoUsed() {
    String digestAlgo = "SHA384";
    String refDigestAlgo = "SHA224";
    String fileName = this.getFileBy("asics");

    invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tst", "-datst", digestAlgo);
    assertThat(this.stdOut.getLog(), StringContains.containsString("Using timestamp digest algorithm " + digestAlgo));

    digestAlgo = "SHA512";
    invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-tst", "-datst", digestAlgo, "-refdatst", refDigestAlgo);
    assertThat(this.stdOut.getLog(), StringContains.containsString("Using timestamp digest algorithm " + digestAlgo));
    assertThat(this.stdOut.getLog(), StringContains.containsString("Using reference digest algorithm " + refDigestAlgo));

    Container container = ContainerOpener.open(fileName);
    Assert.assertTrue(container.validate().isValid());
    Assert.assertEquals(2, container.getTimestamps().size());
    Assert.assertEquals("ASICS", container.getType());

    assertEquals(org.digidoc4j.DigestAlgorithm.SHA384, container.getTimestamps().get(0).getDigestAlgorithm());
    assertEquals(org.digidoc4j.DigestAlgorithm.SHA512, container.getTimestamps().get(1).getDigestAlgorithm());

    AsicArchiveManifest firstTSArchiveManifest = ((AsicSContainerTimestamp) container.getTimestamps().get(0)).getArchiveManifest();
    Assert.assertNull(firstTSArchiveManifest);

    AsicArchiveManifest secondTSArchiveManifest = ((AsicSContainerTimestamp) container.getTimestamps().get(1)).getArchiveManifest();
    Assert.assertNotNull(secondTSArchiveManifest);
    for (AsicArchiveManifest.DataReference ref : secondTSArchiveManifest.getReferencedDataObjects()) {
      Assert.assertEquals(org.digidoc4j.DigestAlgorithm.valueOf(refDigestAlgo).toString(), ref.getDigestAlgorithm());
    }
  }

  @Test
  public void addPKCS12Signature_ContainerAlreadyTimestamped_Error() {
    String fileName = this.getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);

    parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain", "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(this.stdOut.getLog(), StringContains.containsString(
        "Signing of ASiCS container is not supported."));
  }

  @Test
  public void addPKCS12Signature_ContainerTypeIsASICS_Error() {
    String fileName = this.getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/dds_колючей стерне.txt",
        "text/plain", "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(this.stdOut.getLog(), StringContains.containsString("Signing of ASiCS container is not supported."));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
