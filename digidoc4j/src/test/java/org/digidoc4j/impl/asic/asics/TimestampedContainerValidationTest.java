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

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.test.TestAssert;
import org.junit.Test;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

public class TimestampedContainerValidationTest extends AbstractTest {

  @Test
  public void validate_WhenAsicsWithOneValidTimestamp_ValidationResultContainsInfoAboutOneValidTimestamp() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/testtimestamp.asics",
            configuration
    );

    ContainerValidationResult validationResult = container.validate();

    assertContainerIsValid(validationResult);
    // TODO (DD4J-1076): verify proper attributes of the validation result
    assertThat(validationResult.getSimpleReports(), hasSize(1));
    assertThat(validationResult.getSimpleReports().get(0).getTimestampIdList(), hasSize(1));
    for (String timestampId : validationResult.getSimpleReports().get(0).getTimestampIdList()) {
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
    // TODO (DD4J-1076): verify proper attributes of the validation result
    assertThat(validationResult.getSimpleReports(), hasSize(1));
    assertThat(validationResult.getSimpleReports().get(0).getTimestampIdList(), hasSize(3));
    for (String timestampId : validationResult.getSimpleReports().get(0).getTimestampIdList()) {
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
            "T-0824D9A21AEC5EB4AE77E302F43824D78183F801B77F61ED2E228CEDD98F1C75) - The reference data object is not intact!",
            "T-9113DB064A02F195B5947CB49A3DA81868B7AFB7FCF4001FDF6B95929D6762C0) - The reference data object is not intact!"
    );
    // TODO (DD4J-1076): verify proper attributes of the validation result
    assertThat(validationResult.getReport(), containsString("HASH_FAILURE"));
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
