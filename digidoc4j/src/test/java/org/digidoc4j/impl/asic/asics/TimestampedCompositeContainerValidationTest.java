/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Test;

import java.nio.file.Paths;
import java.time.Instant;
import java.util.Date;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsErrors;
import static org.digidoc4j.test.TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToSignatureUniqueIdList;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToTimestampUniqueIdList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class TimestampedCompositeContainerValidationTest extends AbstractTest {

  @Test
  public void validate_WhenAsicsWithOneValidTimestampAndNestedContainerIsValidBdoc_ValidationResultContainsAggregatedInfo() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/1xTST-valid-bdoc-data-file.asics",
            configuration
    );
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureReports(), hasSize(1));
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(containerValidationResult.getSubIndication(signatureId), nullValue());
      assertThat(containerValidationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-03-27T12:42:57Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Test
  public void validate_WhenAsicsWithTwoValidTimestampsAndNestedContainerIsValidBdoc_ValidationResultContainsAggregatedInfo() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/2xTST-valid-bdoc-data-file.asics",
            configuration
    );
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureReports(), hasSize(1));
    assertThat(containerValidationResult.getTimestampReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(2));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(containerValidationResult.getSubIndication(signatureId), nullValue());
      assertThat(containerValidationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-03-27T12:42:57Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023R"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-08-26T13:31:34Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Test
  public void validate_WhenAsicsWithOneInvalidTimestampAndNestedContainerIsValidBdoc_ValidationResultContainsAggregatedInfo() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/invalid-containers/1xTST-valid-bdoc-data-file-hash-failure-in-tst.asics",
            configuration
    );
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsInvalid(containerValidationResult);
    assertContainsErrors(containerValidationResult.getErrors(),
            container.getTimestamps().get(0).getUniqueId() + ") - The time-stamp message imprint is not intact!"
    );
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureReports(), hasSize(1));
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(containerValidationResult.getSubIndication(signatureId), nullValue());
      assertThat(containerValidationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-03-27T12:42:57Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsErrors(timestampValidationResult.getErrors(),
              timestampId + ") - The time-stamp message imprint is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Test
  public void validate_WhenTimestampedNestedContainerIsAsiceWithExpiredOcspAndSigner_ValidationResultContainsAggregatedInfo() {
    // This test container contains an ASiC-E container with a signature which already had an expired OCSP and signer
    //  certificate prior to wrapping it into a timestamped ASiC-S container.
    //  But expired OCSP nor signer make no difference for Estonian validation policy, so the ASiC-S timestamp token
    //  does not currently add any value.
    // The signature timestamp of the inner container will expire in 01.12.2025.
    //  Either that event, or when the timestamping authority will be withdrawn in TSL, might trigger changes between
    //  the validation results of the whole set vs. the inner container alone.
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/1xTST-asice-datafile-with-expired-signer-and-ocsp.asics",
            configuration
    );
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureReports(), hasSize(1));
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(containerValidationResult.getSubIndication(signatureId), nullValue());
      assertThat(containerValidationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-08-26T13:19:53Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Test
  public void validate_WhenTimestampedNestedContainerIsInvalidAsiceWithMultipleSignatures_ValidationResultContainsAggregatedInfo() {
    String path = "src/test/resources/testFiles/invalid-containers/one-valid-and-multiple-invalid-signatures.asice";
    Container nestedContainer = TestDataBuilderUtil.open(path, configuration);
    Container container = new AsicSCompositeContainer(nestedContainer, Paths.get(path).getFileName().toString(), configuration);
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsInvalid(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getErrors(), 14,
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The reference data object has not been found!",
            "(Signature ID: id-6128479cd68e028c5d2a51bed115534f) - The reference data object is not intact!",
            "(Signature ID: id-6fe708387ee0f33f7112fb02f72e8044) - The reference data object is not intact!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The signature is not intact!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The time-stamp message imprint is not intact!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - Signature has an invalid timestamp",
            "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The signing certificate digest value does not match!",
            "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The reference data object is not intact!",
            "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - The time-stamp message imprint is not intact!",
            "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - Signature has an invalid timestamp",
            "(Signature ID: id-a4b5f8ff7fc270bc86b3ff9f12b5a84c) - The difference between the OCSP response time and the signature timestamp is too large",
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but the signature file for signature id-3c2450a9540e30ef7c89d4bad355065e does not have an entry for this file",
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The signature file for signature id-3c2450a9540e30ef7c89d4bad355065e has an entry for file <test.xtx> with mimetype <text/plain> but the manifest file does not have an entry for this file",
            "(Signature ID: id-07db1cabd904a28dcfe0b6779eafbebc) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but the signature file for signature id-07db1cabd904a28dcfe0b6779eafbebc indicates the mimetype is <text/xml>"
    );
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getWarnings(), 6,
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The signature/seal is an INDETERMINATE AdES digital signature!",
            "(Signature ID: id-6128479cd68e028c5d2a51bed115534f) - The signature/seal is not a valid AdES digital signature!",
            "(Signature ID: id-6fe708387ee0f33f7112fb02f72e8044) - The signature/seal is not a valid AdES digital signature!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The signature/seal is not a valid AdES digital signature!",
            "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The signature/seal is an INDETERMINATE AdES digital signature!",
            "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - The computed message-imprint does not match the value extracted from the time-stamp!"
    );
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getContainerErrors(), 3,
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but the signature file for signature id-3c2450a9540e30ef7c89d4bad355065e does not have an entry for this file",
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The signature file for signature id-3c2450a9540e30ef7c89d4bad355065e has an entry for file <test.xtx> with mimetype <text/plain> but the manifest file does not have an entry for this file",
            "(Signature ID: id-07db1cabd904a28dcfe0b6779eafbebc) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but the signature file for signature id-07db1cabd904a28dcfe0b6779eafbebc indicates the mimetype is <text/xml>"
    );
    assertThat(containerValidationResult.getContainerWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(10));
    assertThat(containerValidationResult.getSignatureReports(), hasSize(9));
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(9));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = nestedContainer.getSignatures().get(1).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The reference data object has not been found!"
      );
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getWarnings(), 1,
              "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The signature/seal is an INDETERMINATE AdES digital signature!"
      );
    }
    {
      String signatureId = nestedContainer.getSignatures().get(2).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "(Signature ID: id-6128479cd68e028c5d2a51bed115534f) - The reference data object is not intact!"
      );
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getWarnings(), 1,
              "(Signature ID: id-6128479cd68e028c5d2a51bed115534f) - The signature/seal is not a valid AdES digital signature!"
      );
    }
    {
      String signatureId = nestedContainer.getSignatures().get(3).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "(Signature ID: id-6fe708387ee0f33f7112fb02f72e8044) - The reference data object is not intact!"
      );
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getWarnings(), 1,
              "(Signature ID: id-6fe708387ee0f33f7112fb02f72e8044) - The signature/seal is not a valid AdES digital signature!"
      );
    }
    {
      String signatureId = nestedContainer.getSignatures().get(4).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 3,
              "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The signature is not intact!",
              "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The time-stamp message imprint is not intact!",
              "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - Signature has an invalid timestamp"
      );
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getWarnings(), 1,
              "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The signature/seal is not a valid AdES digital signature!"
      );
    }
    {
      String signatureId = nestedContainer.getSignatures().get(5).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 2,
              "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The signing certificate digest value does not match!",
              "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The reference data object is not intact!"
      );
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getWarnings(), 1,
              "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The signature/seal is an INDETERMINATE AdES digital signature!"
      );
    }
    {
      String signatureId = nestedContainer.getSignatures().get(6).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 2,
              "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - The time-stamp message imprint is not intact!",
              "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - Signature has an invalid timestamp"
      );
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getWarnings(), 1,
              "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - The computed message-imprint does not match the value extracted from the time-stamp!"
      );
    }
    {
      String signatureId = nestedContainer.getSignatures().get(7).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "(Signature ID: id-a4b5f8ff7fc270bc86b3ff9f12b5a84c) - The difference between the OCSP response time and the signature timestamp is too large"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      // Currently this introduces container error about data file mimetype mismatch between signature and manifest,
      //  but the signature itself is considered valid
      String signatureId = nestedContainer.getSignatures().get(8).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsInvalid(nestedValidationResult);
    assertThat(nestedValidationResult.getErrors(), hasSize(14));
    assertThat(nestedValidationResult.getWarnings(), hasSize(6));
    assertThat(nestedValidationResult.getContainerErrors(), hasSize(3));
    assertThat(nestedValidationResult.getContainerWarnings(), empty());
  }

  @Test
  public void validate_WhenTimestampedNestedContainerIsValidDdoc_ValidationResultContainsAggregatedInfo() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/1xTST-valid-ddoc-data-file.asics",
            configuration
    );
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(signatureId), nullValue());
      assertThat(containerValidationResult.getSubIndication(signatureId), nullValue());
      assertThat(containerValidationResult.getSignatureQualification(signatureId), nullValue());
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-10-07T06:17:25Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Test
  public void validate_WhenTimestampedNestedContainerIsInvalidDdocWithMultipleSignatures_ValidationResultContainsAggregatedInfo() {
    String path = "src/test/resources/testFiles/invalid-containers/one-valid-and-multiple-invalid-signatures.ddoc";
    Container nestedContainer = TestDataBuilderUtil.open(path, configuration);
    Container container = new AsicSCompositeContainer(nestedContainer, Paths.get(path).getFileName().toString(), configuration);
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());

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
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(7));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String signatureId = nestedContainer.getSignatures().get(1).getUniqueId();
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
      String signatureId = nestedContainer.getSignatures().get(2).getUniqueId();
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
      String signatureId = nestedContainer.getSignatures().get(3).getUniqueId();
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
      String signatureId = nestedContainer.getSignatures().get(4).getUniqueId();
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
      String signatureId = nestedContainer.getSignatures().get(5).getUniqueId();
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
      String signatureId = nestedContainer.getSignatures().get(6).getUniqueId();
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getErrors(), 1,
              "ERROR: 90 - Signature has no OCSP confirmation!"
      );
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsInvalid(nestedValidationResult);
    assertThat(nestedValidationResult.getErrors(), hasSize(7));
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    // TODO (DD4J-1123): Currently JDigiDoc configuration (for validating DDoc containers and signatures) is
    //  automatically initialized only once per process, and thus is dependent on the order the unit tests are run.
    //  This workaround helps to avoid unit test failures caused by incompatible configuration being loaded.
    ConfigManager.init(configuration.getDDoc4JConfiguration());
  }

}
