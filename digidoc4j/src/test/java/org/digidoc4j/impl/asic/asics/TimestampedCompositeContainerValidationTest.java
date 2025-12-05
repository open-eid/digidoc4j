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
import org.digidoc4j.CompositeContainerBuilder;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.digidoc4j.test.TestConstants;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Test;

import java.nio.file.Paths;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValidIgnoreErrors;
import static org.digidoc4j.test.TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages;
import static org.digidoc4j.test.TestAssert.assertContainsExactSetOfErrors;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToIsoDate;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToSignatureUniqueIdList;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToTimestampUniqueIdList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
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
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-03-27T12:42:57Z"));
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
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-03-27T12:42:57Z"));
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
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023R_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-08-26T13:31:34Z"));
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
    assertContainsExactSetOfErrors(containerValidationResult.getErrors(),
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
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-03-27T12:42:57Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsExactSetOfErrors(timestampValidationResult.getErrors(),
              timestampId + ") - The time-stamp message imprint is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Test
  public void validate_WhenAsicsWithInvalidAndNonCoveringTimestampAndNestedContainerIsValidBdoc_ValidationResultContainsAggregatedInfo() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/invalid-containers/2xTST-valid-bdoc-data-file-1st-tst-invalid-2nd-tst-no-coverage.asics",
            configuration
    );
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValidIgnoreErrors(containerValidationResult);
    assertContainsExactSetOfErrors(containerValidationResult.getErrors(),
            container.getTimestamps().get(0).getUniqueId() + ") - The time-stamp message imprint is not intact!"
    );
    assertContainsExactSetOfErrors(containerValidationResult.getWarnings(),
            container.getTimestamps().get(1).getUniqueId() + ") - The time-stamp token does not cover container datafile!"
    );
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
      assertThat(signatureValidationResult.isValid(), is(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-03-27T12:42:57Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      assertThat(timestampReport.getErrors(), contains("The time-stamp message imprint is not intact!"));
      assertThat(timestampReport.getWarnings(), empty());
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), is(false));
      assertContainsExactSetOfErrors(timestampValidationResult.getErrors(),
              timestampId + ") - The time-stamp message imprint is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-09-11T06:03:34Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      assertThat(timestampReport.getErrors(), empty());
      assertThat(timestampReport.getWarnings(), contains(
              "The time-stamp token does not cover container datafile!"
      ));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), is(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertContainsExactSetOfErrors(timestampValidationResult.getWarnings(),
              timestampId + ") - The time-stamp token does not cover container datafile!"
      );
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Test
  public void validate_WhenAsicsWithInvalidAndNonCoveringAndValidTimestampAndNestedContainerIsValidBdoc_ValidationResultContainsAggregatedInfo() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/3xTST-valid-bdoc-data-file-1st-tst-invalid-2nd-tst-no-coverage-3rd-tst-valid.asics",
            configuration
    );
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValidIgnoreErrors(containerValidationResult);
    assertContainsExactSetOfErrors(containerValidationResult.getErrors(),
            container.getTimestamps().get(0).getUniqueId() + ") - The time-stamp message imprint is not intact!"
    );
    assertContainsExactSetOfErrors(containerValidationResult.getWarnings(),
            container.getTimestamps().get(1).getUniqueId() + ") - The time-stamp token does not cover container datafile!"
    );
    assertThat(containerValidationResult.getSimpleReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureReports(), hasSize(1));
    assertThat(containerValidationResult.getTimestampReports(), hasSize(3));
    assertThat(containerValidationResult.getSignatureIdList(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), equalToSignatureUniqueIdList(nestedContainer));
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(3));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(containerValidationResult.getSubIndication(signatureId), nullValue());
      assertThat(containerValidationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
      ValidationResult signatureValidationResult = containerValidationResult.getValidationResult(signatureId);
      assertThat(signatureValidationResult, notNullValue());
      assertThat(signatureValidationResult.isValid(), is(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertThat(signatureValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-03-27T12:42:57Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      assertThat(timestampReport.getErrors(), contains("The time-stamp message imprint is not intact!"));
      assertThat(timestampReport.getWarnings(), empty());
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), is(false));
      assertContainsExactSetOfErrors(timestampValidationResult.getErrors(),
              timestampId + ") - The time-stamp message imprint is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-09-11T06:03:34Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      assertThat(timestampReport.getErrors(), empty());
      assertThat(timestampReport.getWarnings(), contains(
              "The time-stamp token does not cover container datafile!"
      ));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), is(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertContainsExactSetOfErrors(timestampValidationResult.getWarnings(),
              timestampId + ") - The time-stamp token does not cover container datafile!"
      );
    }
    {
      String timestampId = container.getTimestamps().get(2).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(2);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-10-25T13:42:07Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      assertThat(timestampReport.getErrors(), empty());
      assertThat(timestampReport.getWarnings(), empty());
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), is(true));
      assertThat(timestampValidationResult.getErrors(), empty());
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
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-08-26T13:19:53Z"));
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
    Container container = CompositeContainerBuilder
            .fromContainer(nestedContainer, Paths.get(path).getFileName().toString())
            .buildTimestamped(timestampBuilder -> {});

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsInvalid(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getErrors(), 13,
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The reference name does not match the name of the document!",
            "(Signature ID: id-6128479cd68e028c5d2a51bed115534f) - The reference data object is not intact!",
            "(Signature ID: id-6fe708387ee0f33f7112fb02f72e8044) - The reference data object is not intact!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The signature is not intact!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The time-stamp message imprint is not intact!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - Signature has an invalid timestamp",
            "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The signing certificate digest value does not match!",
            "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The reference data object is not intact!",
            "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - The time-stamp message imprint is not intact!",
            "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - Signature has an invalid timestamp",
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but the signature file for signature id-3c2450a9540e30ef7c89d4bad355065e does not have an entry for this file",
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The signature file for signature id-3c2450a9540e30ef7c89d4bad355065e has an entry for file <test.xtx> with mimetype <text/plain> but the manifest file does not have an entry for this file",
            "(Signature ID: id-07db1cabd904a28dcfe0b6779eafbebc) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but the signature file for signature id-07db1cabd904a28dcfe0b6779eafbebc indicates the mimetype is <text/xml>"
    );
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getWarnings(), 7,
            "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The signature/seal is an INDETERMINATE AdES digital signature!",
            "(Signature ID: id-6128479cd68e028c5d2a51bed115534f) - The signature/seal is not a valid AdES digital signature!",
            "(Signature ID: id-6fe708387ee0f33f7112fb02f72e8044) - The signature/seal is not a valid AdES digital signature!",
            "(Signature ID: id-cd8654a26c4f2a00f9d77d20a280aade) - The signature/seal is not a valid AdES digital signature!",
            "(Signature ID: id-11b9536c6b07506f4dd5b2a772258f87) - The signature/seal is an INDETERMINATE AdES digital signature!",
            "(Signature ID: id-811fee53ac96b318b0a9c092dc86f7ef) - The computed message-imprint does not match the value extracted from the time-stamp!",
            "(Signature ID: id-a4b5f8ff7fc270bc86b3ff9f12b5a84c) - The time difference between the signature timestamp and the OCSP response exceeds 15 minutes, rendering the OCSP response not 'fresh'."
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
              "(Signature ID: id-3c2450a9540e30ef7c89d4bad355065e) - The reference name does not match the name of the document!"
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
      assertThat(signatureValidationResult.isValid(), equalTo(true));
      assertThat(signatureValidationResult.getErrors(), empty());
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              signatureValidationResult.getWarnings(), 1,
              "(Signature ID: id-a4b5f8ff7fc270bc86b3ff9f12b5a84c) - The time difference between the signature timestamp and the OCSP response exceeds 15 minutes, rendering the OCSP response not 'fresh'."
      );
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
    assertThat(nestedValidationResult.getErrors(), hasSize(13));
    assertThat(nestedValidationResult.getWarnings(), hasSize(7));
    assertThat(nestedValidationResult.getContainerErrors(), hasSize(3));
    assertThat(nestedValidationResult.getContainerWarnings(), empty());
  }

  @Test
  public void validate_WhenAsicsWithTimeStampBeforeTeraSupportEndAndNestedContainerIsDdoc_ContainerValidationResultHasNoSha1WarningNestedValidationResultHasSha1Warning(){
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);

    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/timestamptoken-ddoc.asics", configuration);
    Container nestedContainer = TestDataBuilderUtil.open(
            container.getDataFiles().get(0),
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertContainsExactSetOfErrors(containerValidationResult.getWarnings(),
            "(Signature ID: T-D1EEC694EF475DCFAEBC2B3C82A734AC655072FBA3E6E36EAD5166C19DFF3128) - " +
                    "The certificate is not related to a granted status at time-stamp lowest POE time!");
    assertContainsExactSetOfErrors(containerValidationResult.getContainerWarnings(),
            "Found a timestamp token not related to granted status. " +
                    "If not yet covered with a fresh timestamp token, this container might become invalid in the future."
    );
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
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
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.TSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2017-08-17T09:35:32Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertContainsExactSetOfErrors(containerValidationResult.getWarnings(),
              "(Signature ID: " + timestampId + ") - " +
                      "The certificate is not related to a granted status at time-stamp lowest POE time!"
      );
    }

    // Validate the nested DDOC container separately —
    // unlike the outer ASiC-S (timestamped before Tera support ended),
    // the DDOC itself uses the deprecated SHA-1 algorithm and should produce a SHA-1 warning.
    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
    assertContainsExactSetOfErrors(nestedValidationResult.getContainerWarnings(),
            "The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"
    );
  }

  @Test
  public void validate_WhenAsicsWithTimestampAfterTeraSupportAndNestedContainerIsValidDdocWithSha1Warning_ValidationResultContainsAggregatedInfo() {
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
    assertContainsExactSetOfErrors(containerValidationResult.getContainerWarnings(),
            "The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"
    );
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
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-10-07T06:17:25Z"));
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
    assertThat(nestedValidationResult.getContainerWarnings(), hasSize(1));
  }

  @Test
  public void validate_WhenAsicsWithTimestampAfterTeraSupportAndNestedContainerIsInvalidDdocWithMultipleSignaturesAndSha1Warning_ValidationResultContainsAggregatedInfo() {
    String path = "src/test/resources/testFiles/invalid-containers/one-valid-and-multiple-invalid-signatures.ddoc";
    Container nestedContainer = TestDataBuilderUtil.open(path, configuration);
    Container container = CompositeContainerBuilder
            .fromContainer(nestedContainer, Paths.get(path).getFileName().toString())
            .buildTimestamped(timestampBuilder -> {});

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
    assertContainsExactSetOfErrors(containerValidationResult.getContainerWarnings(),
            "The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"
    );
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
    assertThat(nestedValidationResult.getContainerWarnings(), hasSize(1));
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
