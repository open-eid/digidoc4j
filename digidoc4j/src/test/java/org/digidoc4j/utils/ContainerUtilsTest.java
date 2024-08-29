/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ContainerUtilsTest {

  @Test
  public void getMimeTypeStringFor_WhenContainerIsNull_ReturnsApplicationOctetStream() {
    String result = ContainerUtils.getMimeTypeStringFor(null);

    assertThat(result, equalTo("application/octet-stream"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsMock_ReturnsApplicationOctetStream() {
    Container mockedContainer = mock(Container.class);

    String result = ContainerUtils.getMimeTypeStringFor(mockedContainer);

    assertThat(result, equalTo("application/octet-stream"));
    verify(mockedContainer).getType();
    verifyNoMoreInteractions(mockedContainer);
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsAsice_ReturnsAsiceMimeTypeString() {
    Container asiceContainer = ContainerBuilder
            .aContainer(Container.DocumentType.ASICE)
            .build();

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/vnd.etsi.asic-e+zip"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsAsics_ReturnsAsicsMimeTypeString() {
    Container asiceContainer = ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .build();

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/vnd.etsi.asic-s+zip"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsBdoc_ReturnsAsiceMimeTypeString() {
    Container asiceContainer = ContainerBuilder
            .aContainer(Container.DocumentType.BDOC)
            .build();

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/vnd.etsi.asic-e+zip"));
  }

  @Test
  public void getMimeTypeStringFor_WhenContainerIsDdoc_ReturnsDdocMimeTypeString() {
    Container asiceContainer = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc");

    String result = ContainerUtils.getMimeTypeStringFor(asiceContainer);

    assertThat(result, equalTo("application/x-ddoc"));
  }

}
