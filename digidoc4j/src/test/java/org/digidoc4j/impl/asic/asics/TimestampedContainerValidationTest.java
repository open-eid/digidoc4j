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
import org.digidoc4j.Timestamp;
import org.digidoc4j.test.TestAssert;
import org.junit.Test;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class TimestampedContainerValidationTest extends AbstractTest {

  @Test
  public void validate_WhenAsicsWithOneValidTimestamp_ValidationResultContainsInfoAboutOneValidTimestamp() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/testtimestamp.asics",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
    assertThat(validationResult.getSimpleReports(), hasSize(1));
    assertThat(validationResult.getSimpleReports().get(0).getTimestampIdList(), hasSize(1));
    assertThat(validationResult.getTimestampReports(), hasSize(1));
    for (Timestamp timestamp : container.getTimestamps()) {
      String timestampId = timestamp.getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(validationResult.getSubIndication(timestampId), nullValue());
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      assertThat(
              validationResult.getSimpleReports().get(0).getProducedBy(timestampId),
              equalTo("DEMO of SK TSA 2014")
      );
    }
  }

  @Test
  public void validate_WhenAsicsWith3ValidTimestamps_ValidationResultContainsInfoAbout3ValidTimestamps() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/3xTST-text-data-file.asics",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
    assertThat(validationResult.getSimpleReports(), hasSize(1));
    assertThat(validationResult.getSimpleReports().get(0).getTimestampIdList(), hasSize(3));
    assertThat(validationResult.getTimestampReports(), hasSize(3));
    for (Timestamp timestamp : container.getTimestamps()) {
      String timestampId = timestamp.getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(validationResult.getSubIndication(timestampId), nullValue());
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      assertThat(
              validationResult.getSimpleReports().get(0).getProducedBy(timestampId),
              equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023E")
      );
    }
  }

  @Test
  public void validate_WhenAsicsWith1ValidAnd2InvalidTimestamps_ValidationResultContainsErrors() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/invalid-containers/3xTST-text-data-file-hash-failure-since-2nd-tst.asics",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsInvalid(validationResult);
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            container.getTimestamps().subList(1, 3).stream()
                    .map(Timestamp::getUniqueId)
                    .map(id -> id + ") - The reference data object is not intact!")
                    .toArray(String[]::new)
    );
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(validationResult.getSubIndication(timestampId), nullValue());
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(validationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
    }
    {
      String timestampId = container.getTimestamps().get(2).getUniqueId();
      assertThat(validationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(validationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(validationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
    }
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
