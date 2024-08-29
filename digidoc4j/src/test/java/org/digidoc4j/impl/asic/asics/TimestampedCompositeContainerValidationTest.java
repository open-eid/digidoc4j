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
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsErrors;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
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

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
    assertThat(validationResult.getWarnings(), empty());
    assertThat(validationResult.getSimpleReports(), hasSize(2));
    assertThat(validationResult.getSignatureReports(), hasSize(1));
    assertThat(validationResult.getTimestampReports(), hasSize(1));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(validationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(validationResult.getSubIndication(signatureId), nullValue());
      assertThat(validationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(validationResult.getSubIndication(timestampId), nullValue());
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = validationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-03-27T12:42:57Z"))));
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

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
    assertThat(validationResult.getWarnings(), empty());
    assertThat(validationResult.getSimpleReports(), hasSize(2));
    assertThat(validationResult.getSignatureReports(), hasSize(1));
    assertThat(validationResult.getTimestampReports(), hasSize(2));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(validationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(validationResult.getSubIndication(signatureId), nullValue());
      assertThat(validationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(validationResult.getSubIndication(timestampId), nullValue());
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = validationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-03-27T12:42:57Z"))));
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(validationResult.getSubIndication(timestampId), nullValue());
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = validationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023R"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-08-26T13:31:34Z"))));
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

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsInvalid(validationResult);
    assertContainsErrors(validationResult.getErrors(),
            "The time-stamp message imprint is not intact!"
    );
    assertThat(validationResult.getWarnings(), empty());
    assertThat(validationResult.getSimpleReports(), hasSize(2));
    assertThat(validationResult.getSignatureReports(), hasSize(1));
    assertThat(validationResult.getTimestampReports(), hasSize(1));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(validationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(validationResult.getSubIndication(signatureId), nullValue());
      assertThat(validationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(validationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = validationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-03-27T12:42:57Z"))));
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

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
    assertThat(validationResult.getWarnings(), empty());
    assertThat(validationResult.getSimpleReports(), hasSize(2));
    assertThat(validationResult.getSignatureReports(), hasSize(1));
    assertThat(validationResult.getTimestampReports(), hasSize(1));
    {
      String signatureId = nestedContainer.getSignatures().get(0).getUniqueId();
      assertThat(validationResult.getIndication(signatureId), sameInstance(Indication.TOTAL_PASSED));
      assertThat(validationResult.getSubIndication(signatureId), nullValue());
      assertThat(validationResult.getSignatureQualification(signatureId), sameInstance(SignatureQualification.QESIG));
    }
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(validationResult.getSubIndication(timestampId), nullValue());
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = validationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-08-26T13:19:53Z"))));
    }

    ContainerValidationResult nestedValidationResult = nestedContainer.validate();

    assertContainerIsValid(nestedValidationResult);
    assertThat(nestedValidationResult.getWarnings(), empty());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
