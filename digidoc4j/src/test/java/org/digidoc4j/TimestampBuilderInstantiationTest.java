/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.asic.asics.AsicSContainerTimestampBuilder;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TimestampBuilderInstantiationTest extends AbstractTest {

  @Test
  public void aTimestamp_WhenNewContainerTypeIsAsice_ThrowsException() {
    aTimestamp_WhenNewContainerIsOfUnsupportedType_ThrowsException(Container.DocumentType.ASICE);
  }

  @Test
  public void aTimestamp_WhenNewContainerTypeIsBdoc_ThrowsException() {
    aTimestamp_WhenNewContainerIsOfUnsupportedType_ThrowsException(Container.DocumentType.BDOC);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void aTimestamp_WhenNewContainerIsOfUnsupportedType_ThrowsException(Container.DocumentType containerType) {
    Container container = ContainerBuilder.aContainer(containerType).build();

    UnsupportedFormatException caughtException = assertThrows(
            UnsupportedFormatException.class,
            () -> TimestampBuilder.aTimestamp(container)
    );

    assertThat(caughtException.getMessage(), equalTo("Unsupported format: " + containerType.name()));
  }

  @Test
  public void aTimestamp_WhenNewContainerTypeIsAsics_ReturnsAsicsContainerTimestampBuilder() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).build();

    TimestampBuilder result = TimestampBuilder.aTimestamp(container);

    assertThat(result, instanceOf(AsicSContainerTimestampBuilder.class));
  }

  @Test
  public void aTimestamp_WhenExistingContainerTypeIsAsice_ThrowsException() {
    aTimestamp_WhenExistingContainerIsOfUnsupportedType_ThrowsException(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            Constant.ASICE_CONTAINER_TYPE
    );
  }

  @Test
  public void aTimestamp_WhenExistingContainerTypeIsBdoc_ThrowsException() {
    aTimestamp_WhenExistingContainerIsOfUnsupportedType_ThrowsException(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm-newer.bdoc",
            Constant.BDOC_CONTAINER_TYPE
    );
  }

  @Test
  public void aTimestamp_WhenExistingContainerTypeIsDdoc_ThrowsException() {
    aTimestamp_WhenExistingContainerIsOfUnsupportedType_ThrowsException(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc",
            Constant.DDOC_CONTAINER_TYPE
    );
  }

  @Test
  public void aTimestamp_WhenExistingContainerTypeIsPades_ThrowsException() {
    aTimestamp_WhenExistingContainerIsOfUnsupportedType_ThrowsException(
            "src/test/resources/testFiles/valid-containers/valid-pades-esteid2018.pdf",
            Constant.PADES_CONTAINER_TYPE
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void aTimestamp_WhenExistingContainerIsOfUnsupportedType_ThrowsException(String containerPath, String expectedFormat) {
    Container container = ContainerOpener.open(containerPath, configuration);

    UnsupportedFormatException caughtException = assertThrows(
            UnsupportedFormatException.class,
            () -> TimestampBuilder.aTimestamp(container)
    );

    assertThat(caughtException.getMessage(), equalTo("Unsupported format: " + expectedFormat));
  }

  @Test
  public void aTimestamp_WhenExistingContainerTypeIsAsics_ReturnsAsicsContainerTimestampBuilder() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asics-esteid2018.asics",
            configuration
    );

    TimestampBuilder result = TimestampBuilder.aTimestamp(container);

    assertThat(result, instanceOf(AsicSContainerTimestampBuilder.class));
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
