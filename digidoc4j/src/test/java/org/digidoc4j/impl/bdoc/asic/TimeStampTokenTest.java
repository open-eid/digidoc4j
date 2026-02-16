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
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.exceptions.IllegalContainerContentException;
import org.digidoc4j.exceptions.IllegalTimestampException;
import org.digidoc4j.impl.asic.AsicCompositeContainerValidationResult;
import org.digidoc4j.impl.asic.TimeStampContainerValidationResult;
import org.digidoc4j.impl.asic.asics.AsicSContainerTimestamp;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.TestConstants;
import org.digidoc4j.test.util.TestSigningUtil;
import org.hamcrest.core.StringContains;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.digidoc4j.main.TestDigiDoc4JUtil.invokeDigiDoc4jAndReturnExitStatus;
import static org.digidoc4j.main.TestDigiDoc4JUtil.invokeDigiDoc4jAndReturnInvocationResult;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsExactSetOfErrors;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by Andrei on 22.11.2017.
 */

public class TimeStampTokenTest extends AbstractTest {

  public static final String META_INF_TIMESTAMP_TST = "META-INF/timestamp.tst";

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test
  public void buildTimestampedContainer_ReadFromFile_ValidationSuccess() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(configuration).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").
        withTimeStampToken(DigestAlgorithm.SHA256).build();
    container.saveAsFile(getFileBy("asics"));
    assertContainerIsValid(container);
    assertNotNull(container.getTimeStampToken());
  }

  @Test
  public void buildTimestampedContainer_ReadFromFile_ValidAndHasTimestampToken() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/testtimestamp.asics").build();
    assertContainerIsValid(container);
    assertNotNull(container.getTimeStampToken());
    assertEquals(2001, container.getTimeStampToken().getBytes().length);
  }

  @Test
  public void buildTimestampedContainer_TimeStampWithdrawn_ValidationSucceedsWithWarning() {
    // TODO (DD4J-1123): Currently JDigiDoc configuration (for validating DDoc containers and signatures) is
    //  automatically initialized only once per process, and thus is dependent on the order the unit tests are run.
    //  This workaround helps to avoid unit test failures caused by incompatible configuration being loaded.
    ConfigManager.init(Configuration.getInstance().getDDoc4JConfiguration());

    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/timestamptoken-ddoc.asics").build();
    AsicCompositeContainerValidationResult validationResult = (AsicCompositeContainerValidationResult) container.validate();
    TimeStampContainerValidationResult timestampValidationResult = (TimeStampContainerValidationResult) validationResult.getNestingContainerValidationResult();
    assertEquals(TestConstants.SK_TSA_CN, timestampValidationResult.getSignedBy());
    assertEquals(Indication.TOTAL_PASSED, timestampValidationResult.getIndication());
    assertContainerIsValid(validationResult);
    assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "The certificate is not related to a granted status at time-stamp lowest POE time!");
  }

  @Test
  public void buildTimestampedContainer_ContainerHasValidTimeStamp_ValidationSuccess() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).withConfiguration(configuration).
            fromExistingFile("src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics").build();
    TimeStampContainerValidationResult validate = (TimeStampContainerValidationResult) container.validate();
    assertEquals(TestConstants.DEMO_SK_TSA_2023E_CN, validate.getSignedBy());
    assertEquals(Indication.TOTAL_PASSED, validate.getIndication());
    assertContainerIsValid(validate);
  }

  @Test
  public void openTimestampedContainer_WhenContainerContainsTwoDataFiles_ThrowsIllegalContainerContentException() {
    ContainerBuilder builder = ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/timestamptoken-two-data-files.asics");

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            builder::build
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Timestamped ASiC-S container must contain exactly one datafile")
    );
  }

  @Test
  public void validateTimestampedContainer_WhenContainerContainsInvalidTimestampToken_ThrowsIllegalTimestampException() {
    Container container = ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/timestamptoken-invalid.asics")
            .build();

    IllegalTimestampException caughtException = assertThrows(
            IllegalTimestampException.class,
            container::validate
    );

    assertThat(caughtException.getMessage(), equalTo("Invalid timestamp token"));
  }

  @Test
  public void constructTimestampToken_SetTypeAsArchiveTimestamp_ValidationSuccess() throws Exception {
    try (FileInputStream fis = new FileInputStream("src/test/resources/testFiles/tst/timestamp.tst")) {
      TimestampToken token = new TimestampToken(Utils.toByteArray(fis), TimestampType.ARCHIVE_TIMESTAMP);
      assertNotNull(token);
      assertNotNull(token.getGenerationTime());
      assertTrue(Utils.isCollectionNotEmpty(token.getCertificates()));
      assertNull(token.getSignatureAlgorithm());
      assertTrue(token.isSignedBy(token.getCertificates().get(0)));
      assertNotNull(token.getSignatureAlgorithm());
      assertEquals(TimestampType.ARCHIVE_TIMESTAMP, token.getTimeStampType());
      assertEquals(DigestAlgorithm.SHA256, token.getMessageImprint().getAlgorithm());
      assertEquals(SignatureAlgorithm.RSA_SHA512, token.getSignatureAlgorithm());
      assertTrue(Utils.isStringNotBlank(Utils.toBase64(token.getMessageImprint().getValue())));
      assertFalse(token.isSelfSigned());
      assertFalse(token.matchData(new byte[]{1, 2, 3}));
      assertTrue(token.isMessageImprintDataFound());
      assertFalse(token.isMessageImprintDataIntact());
      assertTrue(token.isMessageImprintDataFound());
    }
  }

  @Test
  public void createASICSContainerWithTst_AddOneDataFile_ValidationSuccess() throws Exception {
    String fileName = getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-datst", "SHA256", "-tst"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);

    try (ZipFile zipFile = new ZipFile(fileName)) {
      ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
      ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);
      ZipEntry timestampEntry = zipFile.getEntry(META_INF_TIMESTAMP_TST);

      assertNotNull(mimeTypeEntry);
      assertNotNull(manifestEntry);
      assertNotNull(timestampEntry);

      try (InputStream mimeStream = zipFile.getInputStream(mimeTypeEntry)) {
        String mimeTypeContent = getFileContent(mimeStream);
        assertTrue(mimeTypeContent.contains(MimeTypeEnum.ASICS.getMimeTypeString()));
      }

      try (InputStream manifestStream = zipFile.getInputStream(manifestEntry)) {
        String manifestContent = getFileContent(manifestStream);
        assertTrue(manifestContent.contains(MimeTypeEnum.ASICS.getMimeTypeString()));
      }
    }

    Container container = ContainerOpener.open(fileName);
    ContainerValidationResult validate = container.validate();
    assertContainerIsValid(validate);
    assertEquals("ASICS", container.getType());
  }

  @Test
  public void createASICSContainerWithTst_AddDataFileAndTimestampTwice_Error() {
    String fileName = getFileBy("asics");
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
    String fileName = getFileBy("asics");
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
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tst");
    assertEquals(0, caughtExitStatus);
    String fileName = getFileBy("asics");

    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-tst");
    assertEquals(0, caughtExitStatus);

    Container container = ContainerOpener.open(fileName);
    assertTrue(container.validate().isValid());
    assertEquals(2, container.getTimestamps().size());
    assertEquals("ASICS", container.getType());
  }

  @Test
  public void createASICSContainerWithTst_SpecifyCustomTspSource_SpecifiedTspUsed() {
    String fileName = getFileBy("asics");
    String tspSource = TestConstants.DEMO_TSA_RSA_URL;

    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tspsourcearchive", tspSource, "-tst");

    assertEquals(0, caughtExitStatus);
    assertThat(this.stdOut.getLog(), StringContains.containsString("Following properties will be used for timestamping: TSP Source " + tspSource));
    Container container = ContainerOpener.open(fileName);
    assertTrue(container.validate().isValid());
    assertEquals(1, container.getTimestamps().size());
  }

  @Test
  public void createASICSContainerWithTst_SpecifyCustomNonRoutableTspSource_ErrorCallingTSP() {
    String fileName = getFileBy("asics");
    String tspSource = "http://10.255.255.1/";

    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tspsourcearchive", tspSource, "-tst");

    assertEquals(1, caughtExitStatus);
    assertThat(this.stdOut.getLog(), anyOf(
            StringContains.containsString(String.format("Connection to TSP service <%s> timed out", tspSource)),
            StringContains.containsString(String.format("Unable to process <TSP> POST call for service <%s>", tspSource))
    ));
  }

  @Test
  public void createASICSContainerWithTst_SpecifyDigestAlgo_SpecifiedDigestAlgoUsed() {
    String digestAlgo = "SHA384";
    String refDigestAlgo = "SHA224";
    String fileName = getFileBy("asics");

    invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-tst", "-datst", digestAlgo);
    assertThat(this.stdOut.getLog(), StringContains.containsString("timestamp digest algorithm " + digestAlgo));

    digestAlgo = "SHA512";
    invokeDigiDoc4jAndReturnExitStatus("-in", fileName, "-tst", "-datst", digestAlgo, "-refdatst", refDigestAlgo);
    assertThat(this.stdOut.getLog(), StringContains.containsString("timestamp digest algorithm " + digestAlgo));
    assertThat(this.stdOut.getLog(), StringContains.containsString("reference digest algorithm " + refDigestAlgo));

    Container container = ContainerOpener.open(fileName);
    assertTrue(container.validate().isValid());
    assertEquals(2, container.getTimestamps().size());
    assertEquals("ASICS", container.getType());

    assertEquals(org.digidoc4j.DigestAlgorithm.SHA384, container.getTimestamps().get(0).getDigestAlgorithm());
    assertEquals(org.digidoc4j.DigestAlgorithm.SHA512, container.getTimestamps().get(1).getDigestAlgorithm());

    AsicArchiveManifest firstTSArchiveManifest = ((AsicSContainerTimestamp) container.getTimestamps().get(0)).getArchiveManifest();
    assertNull(firstTSArchiveManifest);

    AsicArchiveManifest secondTSArchiveManifest = ((AsicSContainerTimestamp) container.getTimestamps().get(1)).getArchiveManifest();
    assertNotNull(secondTSArchiveManifest);
    for (AsicArchiveManifest.DataReference ref : secondTSArchiveManifest.getReferencedDataObjects()) {
      assertEquals(org.digidoc4j.DigestAlgorithm.valueOf(refDigestAlgo).toString(), ref.getDigestAlgorithm());
    }
  }

  @Test
  public void addPKCS12Signature_ContainerAlreadyTimestamped_Error() {
    String fileName = getFileBy("asics");
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
    String fileName = getFileBy("asics");
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
    configuration = new Configuration(Configuration.Mode.TEST);
  }

}
