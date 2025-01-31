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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

abstract class AbstractCadesDssFacadeTest<T extends AbstractCadesDssFacade> extends AbstractTest {

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  protected abstract T getDefaultCadesDssFacade();

  @Test
  public void setContainerType_WhenContainerTypeIsAsice_Succeeds() {
    setContainerType_WhenContainerTypeIsSupported_Succeeds(Container.DocumentType.ASICE);
  }

  @Test
  public void setContainerType_WhenContainerTypeIsAsics_Succeeds() {
    setContainerType_WhenContainerTypeIsSupported_Succeeds(Container.DocumentType.ASICS);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void setContainerType_WhenContainerTypeIsSupported_Succeeds(Container.DocumentType containerType) {
    getDefaultCadesDssFacade().setContainerType(containerType);
  }

  @Test
  public void setContainerType_WhenContainerTypeIsBdoc_ThrowsNotSupportedException() {
    setContainerType_WhenContainerTypeIsNotSupported_ThrowsNotSupportedException(Container.DocumentType.BDOC);
  }

  @Test
  public void setContainerType_WhenContainerTypeIsDdoc_ThrowsNotSupportedException() {
    setContainerType_WhenContainerTypeIsNotSupported_ThrowsNotSupportedException(Container.DocumentType.DDOC);
  }

  @Test
  public void setContainerType_WhenContainerTypeIsPades_ThrowsNotSupportedException() {
    setContainerType_WhenContainerTypeIsNotSupported_ThrowsNotSupportedException(Container.DocumentType.PADES);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void setContainerType_WhenContainerTypeIsNotSupported_ThrowsNotSupportedException(Container.DocumentType containerType) {
    T cadesDssFacade = getDefaultCadesDssFacade();

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> cadesDssFacade.setContainerType(containerType)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Not supported: Unsupported container type: " + containerType.name())
    );
  }

  protected void configureAiaSourceAndCertificateSource(T cadesDssFacade) {
    cadesDssFacade.setAiaSource(new DefaultAIASource());
    cadesDssFacade.setCertificateSource(configuration.getTSL());
  }

  protected static List<DSSDocument> getContainerDataFiles(Container container) {
    return container.getDataFiles().stream()
            .map(DataFile::getDocument)
            .collect(Collectors.toList());
  }

  protected static List<TimestampDocumentsHolder> getContainerTimestamps(Container container) {
    return container.getTimestamps().stream()
            .map(TimestampAndManifestPair.class::cast)
            .map(AbstractCadesDssFacadeTest::toTimestampDocumentsHolder)
            .collect(Collectors.toList());
  }

  protected static TimestampDocumentsHolder toTimestampDocumentsHolder(TimestampAndManifestPair timestamp) {
    TimestampDocumentsHolder documentsHolder = new TimestampDocumentsHolder();
    documentsHolder.setTimestampDocument(timestamp.getCadesTimestamp().getTimestampDocument());
    if (timestamp.getArchiveManifest() != null) {
      documentsHolder.setManifestDocument(timestamp.getArchiveManifest().getManifestDocument());
    }
    return documentsHolder;
  }

}
