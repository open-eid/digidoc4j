/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.ddoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.jupiter.api.Test;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages;
import static org.digidoc4j.test.TestAssert.assertContainsExactSetOfErrors;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToSignatureUniqueIdList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationTest extends AbstractTest {

  @Test
  void setInvalidOcspResponder() {
    configuration.setAllowedOcspRespondersForTM("INVALID OCSP RESPONDER");
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsError("OCSP Responder does not meet TM requirements", result.getErrors());
  }

  @Test
  void missingURIAttributeValue() {
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/invalid-containers/23133_ddoc-12.ddoc").build();
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsError("URI Attribute value is required", result.getErrors());
  }

  @Test
  void defaultOcspResponderSuccessful() {
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    assertTrue(result.isValid(), "Result is not valid");
  }

  @Test
  void setInvalidOcspResponderConfigurationYamlParameter() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_ocsp_responders.yaml");
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsError("OCSP Responder does not meet TM requirements", result.getErrors());
  }

  @Test
  void testValidateDDoc10Hashcode() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.getDDoc4JConfiguration().put("DATAFILE_HASHCODE_MODE", "true");
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener
             .open("src/test/resources/prodFiles/valid-containers/SK-XML1_0_hashcode.ddoc");
    SignatureValidationResult result = container.validate();
    assertTrue(result.isValid());
    assertTrue(result.hasWarnings());
    assertEquals(177, result.getWarnings().get(0).getErrorCode());
    assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  void validate_WhenDdocHasOneValidAndMultipleInvalidSignatures_ValidationResultContainsProperInfoForEachSignature() {
    Container container = TestDataBuilderUtil.open(
            "src/test/resources/testFiles/invalid-containers/one-valid-and-multiple-invalid-signatures.ddoc",
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsInvalid(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getErrors(), 7,
            "ERROR: 79 - Bad digest for DataFile: D0",
            "ERROR: 81 - Invalid signature value!",
            "ERROR: 79 - Bad digest for SignedProperties: S2-SignedProperties",
            "ERROR: 71 - OCSP response's nonce doesn't match the requests nonce!",
            "ERROR: 53 - Notary certificates digest doesn't match!",
            "ERROR: 83 - Notarys digest doesn't match!",
            "ERROR: 90 - Signature has no OCSP confirmation!"
    );
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), empty());
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), empty());
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(7));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(container));
    {
      String signatureId = container.getSignatures().get(0).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = container.getSignatures().get(1).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 2,
              "ERROR: 79 - Bad digest for DataFile: D0",
              "ERROR: 81 - Invalid signature value!"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = container.getSignatures().get(2).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 2,
              "ERROR: 79 - Bad digest for SignedProperties: S2-SignedProperties",
              "ERROR: 81 - Invalid signature value!"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = container.getSignatures().get(3).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 2,
              "ERROR: 81 - Invalid signature value!",
              "ERROR: 71 - OCSP response's nonce doesn't match the requests nonce!"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = container.getSignatures().get(4).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "ERROR: 53 - Notary certificates digest doesn't match!"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = container.getSignatures().get(5).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "ERROR: 83 - Notarys digest doesn't match!"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = container.getSignatures().get(6).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "ERROR: 90 - Signature has no OCSP confirmation!"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
  }

  @Test
  void validate_whenDDOCValidated_containerValidationResultContainsSHA1Warning() {
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerBuilder.aContainer()
            .withConfiguration(configuration)
            .fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc")
            .build();

    ContainerValidationResult result = container.validate();

    assertContainerIsValid(result);
    assertContainsExactSetOfErrors(result.getContainerWarnings(),
            "The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"
    );
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }
}
