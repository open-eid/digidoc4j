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
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToTimestampUniqueIdList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class TimestampedContainerValidationTest extends AbstractTest {

  @Test
  public void validate_WhenAsicsWithOneValidTimestamp_ValidationResultContainsInfoAboutOneValidTimestamp() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/testtimestamp.asics",
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO of SK TSA 2014"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2017-11-24T08:20:33Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

  @Test
  public void validate_WhenAsicsWith3ValidTimestamps_ValidationResultContainsInfoAbout3ValidTimestamps() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/3xTST-text-data-file.asics",
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(3));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(3));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-07-05T08:42:57Z"))));
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
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-07-05T08:44:04Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(2).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(2);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-07-05T08:45:10Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

  @Test
  public void validate_WhenAsicsWith1ValidAnd2InvalidTimestamps_ValidationResultContainsErrors() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/invalid-containers/3xTST-text-data-file-hash-failure-since-2nd-tst.asics",
            configuration
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsInvalid(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getErrors(), 2,
            container.getTimestamps().get(1).getUniqueId() + ") - The reference data object is not intact!",
            container.getTimestamps().get(2).getUniqueId() + ") - The reference data object is not intact!"
    );
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(3));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(3));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-05-20T07:58:12Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-05-20T07:59:20Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getErrors(), 1,
              timestampId + ") - The reference data object is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(2).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(2);
      assertThat(timestampReport.getProducedBy(), equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E"));
      assertThat(timestampReport.getProductionTime(), equalTo(Date.from(Instant.parse("2024-05-20T08:00:25Z"))));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getErrors(), 1,
              timestampId + ") - The reference data object is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
