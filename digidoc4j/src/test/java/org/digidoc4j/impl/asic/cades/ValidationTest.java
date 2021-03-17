package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DetachedXadesSignatureBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.DigestDataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.asic.asice.AsicESignatureBuilder;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureOpener;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ValidationTest extends AbstractTest {

  @BeforeClass
  public static void setUpOnce() throws Exception {
  }

  @Test
  public void validateAsicContainerWithCades_B_SignatureLevel_isValid() {
    this.configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/test_constraint_b_level.xml");
    Container container = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/valid-containers/asiceWithCades-b-level.asice")
        .withConfiguration(this.configuration)
        .build();
    ContainerValidationResult result = container.validate();
    SimpleReport simpleReport = result.getSimpleReports().get(0);
    Assert.assertEquals(SignatureLevel.CAdES_BASELINE_B, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
    Assert.assertTrue("Container is invalid", result.isValid());
  }

  @Test
  public void validateAsicContainerWithCades_T_SignatureLevel_isValid() {
    this.configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/test_constraint_b_level.xml");
    Container container = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/valid-containers/asiceWithCades-t-level.asice")
        .withConfiguration(this.configuration)
        .build();
    ContainerValidationResult result = container.validate();
    SimpleReport simpleReport = result.getSimpleReports().get(0);
    Assert.assertEquals(SignatureLevel.CAdES_BASELINE_T, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
    Assert.assertTrue("Container is invalid", result.isValid());
  }

  @Test
  public void validateAsicContainerWithCades_LT_SignatureLevel_isValid() {
    Container container = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/valid-containers/asiceWithCades-lt-level.asice")
        .withConfiguration(this.configuration)
        .build();
    ContainerValidationResult result = container.validate();
    SimpleReport simpleReport = result.getSimpleReports().get(0);
    Assert.assertEquals(SignatureLevel.CAdES_BASELINE_LT, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
    Assert.assertTrue("Container is invalid", result.isValid());
  }

  @Test
  public void validateAsicContainerWithCades_ASICE_documentType() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICE)
        .fromExistingFile("src/test/resources/testFiles/valid-containers/asiceWithCades-lt-level.asice")
        .withConfiguration(this.configuration)
        .build();
    ContainerValidationResult result = container.validate();
    SimpleReport simpleReport = result.getSimpleReports().get(0);
    Assert.assertEquals(SignatureLevel.CAdES_BASELINE_LT, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
    Assert.assertTrue("Container is invalid", result.isValid());
  }

  @Test
  @Ignore("DD4J-498")
  public void validateAsicContainerWithCades_stream_LT_SignatureLevel_isValid() throws FileNotFoundException {
    Container container = ContainerBuilder.aContainer()
        .fromStream(new FileInputStream("src/test/resources/testFiles/valid-containers/asiceWithCades-lt-level.asice"))
        .withConfiguration(this.configuration)
        .build();
    ContainerValidationResult result = container.validate();
    SimpleReport simpleReport = result.getSimpleReports().get(0);
    Assert.assertEquals(SignatureLevel.CAdES_BASELINE_LT, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
    Assert.assertTrue("Container is invalid", result.isValid());
  }

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
  }
}
