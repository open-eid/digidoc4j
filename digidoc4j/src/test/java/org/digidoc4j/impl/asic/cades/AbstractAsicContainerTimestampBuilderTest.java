/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import org.digidoc4j.AbstractTimestampBuilderTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.exceptions.DataFileMissingException;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

public abstract class AbstractAsicContainerTimestampBuilderTest extends AbstractTimestampBuilderTest {

  protected abstract Container getEmptyContainerForTimestamping(Configuration configuration);

  @Test
  public void invokeTimestamping_WhenContainerHasNoDataFiles_ThrowsDataFileMissingException() {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getEmptyContainerForTimestamping(Configuration.of(Configuration.Mode.TEST)));

    DataFileMissingException caughtException = assertThrows(
            DataFileMissingException.class,
            timestampBuilder::invokeTimestamping
    );

    assertThat(caughtException.getMessage(), equalTo("No data files specified, but at least 1 is required"));
  }

}
