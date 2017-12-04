package org.digidoc4j.impl.bdoc.asic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.asic.TimeStampValidationResult;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import eu.europa.esig.dss.DigestAlgorithm;
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

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

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
    Assert.assertNull(validate.getErrors());
    Assert.assertEquals(Indication.TOTAL_PASSED, validate.getIndication());
    assertTrue(validate.isValid());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenContainerTwoDataFiles(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile("testFiles\\invalid-containers\\timestamptoken-two-data-files.asics").
        build();

    ValidationResult validate = container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidTimeStampContainer(){
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile("testFiles\\invalid-containers\\timestamptoken-invalid.asics").
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

}
