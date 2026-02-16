/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.impl.asic.EmptyDataFilesContainerTest;
import org.digidoc4j.test.TestAssert;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EmptyDataFilesAsicSContainerTest extends EmptyDataFilesContainerTest {

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  @Override
  protected Container.DocumentType getDocumentType() {
    return Container.DocumentType.ASICS;
  }

  @Test
  public void testValidateUnsignedContainerWithEmptyDataFile() {
    Container container = loadUnsignedContainerWithEmptyDataFile();

    ContainerValidationResult validationResult = container.validate();

    assertTrue(validationResult.isValid());
    assertNotNull(validationResult.getWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "Data file 'empty-file.txt' is empty"
    );
    assertNotNull(validationResult.getContainerWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getContainerWarnings(),
            "Data file 'empty-file.txt' is empty"
    );
  }

  @Test
  public void testValidateSignedContainerWithEmptyDataFile() {
    Container container = loadSignedContainerWithEmptyDataFile();

    ContainerValidationResult validationResult = container.validate();

    assertTrue(validationResult.isValid());
    assertNotNull(validationResult.getWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "Data file 'empty-file.txt' is empty"
    );
    assertNotNull(validationResult.getContainerWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getContainerWarnings(),
            "Data file 'empty-file.txt' is empty"
    );
  }

  @Test
  public void testValidateTimestampedContainerWithEmptyDataFile() {
    Container container = loadTimestampedContainerWithEmptyDataFile();

    ContainerValidationResult validationResult = container.validate();

    assertTrue(validationResult.isValid());
    assertNotNull(validationResult.getWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "Data file 'empty-file.txt' is empty"
    );
    assertNotNull(validationResult.getContainerWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getContainerWarnings(),
            "Data file 'empty-file.txt' is empty"
    );
  }

  @Test
  public void testInvokeTimestampingForUnsignedContainerWithEmptyDataFile() {
    Container container = loadUnsignedContainerWithEmptyDataFile();

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            () -> TimestampBuilder.aTimestamp(container).invokeTimestamping()
    );

    assertEquals("Cannot timestamp empty datafile: empty-file.txt", caughtException.getMessage());
  }

  @Test
  public void testInvokeTimestampingForTimestampedContainerWithEmptyDataFile() {
    Container container = loadTimestampedContainerWithEmptyDataFile();

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            () -> TimestampBuilder.aTimestamp(container).invokeTimestamping()
    );

    assertEquals("Cannot timestamp empty datafile: empty-file.txt", caughtException.getMessage());
  }

  private Container loadUnsignedContainerWithEmptyDataFile() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/unsigned-container-with-empty-datafile.asics", configuration);
    assertEquals(Constant.ASICS_CONTAINER_TYPE, container.getType());
    return container;
  }

  private Container loadSignedContainerWithEmptyDataFile() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/signed-container-with-empty-datafile.asics", configuration);
    assertEquals(Constant.ASICS_CONTAINER_TYPE, container.getType());
    return container;
  }

  private Container loadTimestampedContainerWithEmptyDataFile() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/timestamped-container-with-empty-datafile.asics", configuration);
    assertEquals(Constant.ASICS_CONTAINER_TYPE, container.getType());
    return container;
  }

}
