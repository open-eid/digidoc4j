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
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertThrows;

public class EmptyDataFilesAsicSContainerTimestampFinalizerTest extends AbstractTest {

  @Test
  public void testCreateTimestampFinalizerWithEmptyDataFile() {
    DataFile dataFile = new DataFile(new byte[0], "empty-file.txt", "text/plain");

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            () -> new AsicSContainerTimestampFinalizer(configuration, dataFile, null)
    );

    Assert.assertEquals("Cannot sign empty datafile: empty-file.txt", caughtException.getMessage());
    TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class);
  }

}
