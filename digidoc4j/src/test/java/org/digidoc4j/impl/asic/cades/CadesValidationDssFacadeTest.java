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

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.sameInstance;

public class CadesValidationDssFacadeTest extends AbstractCadesDssFacadeTest<CadesValidationDssFacade> {

  @Test
  public void openValidator_WhenAsiceWithoutDataFilesAndTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenNoDataFilesAndTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICE, ASiCContainerType.ASiC_E);
  }

  @Test
  public void openValidator_WhenAsicsWithoutDataFilesAndTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenNoDataFilesAndTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICS, ASiCContainerType.ASiC_S);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openValidator_WhenNoDataFilesAndTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator(
          Container.DocumentType dd4jContainerType,
          ASiCContainerType expectedContainerType
  ) {
    CadesValidationDssFacade cadesValidationDssFacade = getDefaultCadesDssFacade();
    cadesValidationDssFacade.setContainerType(dd4jContainerType);
    cadesValidationDssFacade.setDataFiles(Collections.emptyList());
    cadesValidationDssFacade.setTimestamps(Collections.emptyList());

    SignedDocumentValidator signedDocumentValidator = cadesValidationDssFacade.openValidator();

    assertThat(signedDocumentValidator.getSignatures(), empty());
    assertThat(signedDocumentValidator.getDetachedTimestamps(), empty());
    XmlDiagnosticData diagnosticData = signedDocumentValidator.getDiagnosticData();
    assertThat(diagnosticData.getContainerInfo().getContainerType(), sameInstance(expectedContainerType));
    assertThat(diagnosticData.getContainerInfo().getManifestFiles(), empty());
    assertThat(diagnosticData.getContainerInfo().getContentFiles(), empty());
  }

  @Test
  public void openValidator_WhenAsiceWithoutTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenNoTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICE, ASiCContainerType.ASiC_E);
  }

  @Test
  public void openValidator_WhenAsicsWithoutTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenNoTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICS, ASiCContainerType.ASiC_S);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openValidator_WhenNoTimestampsSpecified_ReturnsAppropriateSignedDocumentValidator(
          Container.DocumentType dd4jContainerType,
          ASiCContainerType expectedContainerType
  ) {
    CadesValidationDssFacade cadesValidationDssFacade = getDefaultCadesDssFacade();
    cadesValidationDssFacade.setContainerType(dd4jContainerType);
    cadesValidationDssFacade.setDataFiles(Collections.singletonList(
            new InMemoryDocument("Test.".getBytes(StandardCharsets.UTF_8),  "test.txt", MimeTypeEnum.TEXT)
    ));
    cadesValidationDssFacade.setTimestamps(Collections.emptyList());

    SignedDocumentValidator signedDocumentValidator = cadesValidationDssFacade.openValidator();

    assertThat(signedDocumentValidator.getSignatures(), empty());
    assertThat(signedDocumentValidator.getDetachedTimestamps(), empty());
    XmlDiagnosticData diagnosticData = signedDocumentValidator.getDiagnosticData();
    assertThat(diagnosticData.getContainerInfo().getContainerType(), sameInstance(expectedContainerType));
    assertThat(diagnosticData.getContainerInfo().getManifestFiles(), empty());
    assertThat(diagnosticData.getContainerInfo().getContentFiles(), contains("test.txt"));
  }

  @Test
  public void openValidator_WhenAsiceWithTimestampWithoutManifestSpecified_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenTimestampWithoutManifestSpecified_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICE, ASiCContainerType.ASiC_E);
  }

  @Test
  public void openValidator_WhenAsicsWithTimestampWithoutManifestSpecified_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenTimestampWithoutManifestSpecified_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICS, ASiCContainerType.ASiC_S);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openValidator_WhenTimestampWithoutManifestSpecified_ReturnsAppropriateSignedDocumentValidator(
          Container.DocumentType dd4jContainerType,
          ASiCContainerType expectedContainerType
  ) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics",
            configuration
    );
    CadesValidationDssFacade cadesValidationDssFacade = getDefaultCadesDssFacade();
    cadesValidationDssFacade.setContainerType(dd4jContainerType);
    cadesValidationDssFacade.setDataFiles(getContainerDataFiles(container));
    cadesValidationDssFacade.setTimestamps(getContainerTimestamps(container));

    SignedDocumentValidator signedDocumentValidator = cadesValidationDssFacade.openValidator();

    assertThat(signedDocumentValidator.getSignatures(), empty());
    assertThat(signedDocumentValidator.getDetachedTimestamps(), hasSize(1));
    TimestampToken timestampToken = signedDocumentValidator.getDetachedTimestamps().get(0);
    assertThat(timestampToken.getDSSIdAsString(), equalTo(container.getTimestamps().get(0).getUniqueId()));
    assertThat(timestampToken.getFileName(), equalTo("META-INF/timestamp.tst"));
    assertThat(timestampToken.getTimestampScopes(), hasSize(1));
    assertThat(timestampToken.getTimestampScopes().get(0).getDocumentName(), equalTo("test.txt"));
    XmlDiagnosticData diagnosticData = signedDocumentValidator.getDiagnosticData();
    assertThat(diagnosticData.getContainerInfo().getContainerType(), sameInstance(expectedContainerType));
    assertThat(diagnosticData.getContainerInfo().getManifestFiles(), empty());
    assertThat(diagnosticData.getContainerInfo().getContentFiles(), contains("test.txt"));
  }

  @Test
  public void openValidator_WhenAsiceWithTimestampWithManifestIncluded_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenTimestampWithManifestIncluded_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICE, ASiCContainerType.ASiC_E);
  }

  @Test
  public void openValidator_WhenAsicsWithTimestampWithManifestIncluded_ReturnsAppropriateSignedDocumentValidator() {
    openValidator_WhenTimestampWithManifestIncluded_ReturnsAppropriateSignedDocumentValidator(
            Container.DocumentType.ASICS, ASiCContainerType.ASiC_S);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openValidator_WhenTimestampWithManifestIncluded_ReturnsAppropriateSignedDocumentValidator(
          Container.DocumentType dd4jContainerType,
          ASiCContainerType expectedContainerType
  ) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/2xTST-text-data-file.asics",
            configuration
    );
    CadesValidationDssFacade cadesValidationDssFacade = getDefaultCadesDssFacade();
    cadesValidationDssFacade.setContainerType(dd4jContainerType);
    cadesValidationDssFacade.setDataFiles(getContainerDataFiles(container));
    cadesValidationDssFacade.setTimestamps(getContainerTimestamps(container));

    SignedDocumentValidator signedDocumentValidator = cadesValidationDssFacade.openValidator();

    assertThat(signedDocumentValidator.getSignatures(), empty());
    assertThat(signedDocumentValidator.getDetachedTimestamps(), hasSize(2));
    {
      TimestampToken timestampToken = signedDocumentValidator.getDetachedTimestamps().get(0);
      assertThat(timestampToken.getDSSIdAsString(), equalTo(container.getTimestamps().get(0).getUniqueId()));
      assertThat(timestampToken.getFileName(), equalTo("META-INF/timestamp.tst"));
      assertThat(timestampToken.getTimestampScopes(), hasSize(1));
      assertThat(timestampToken.getTimestampScopes().get(0).getDocumentName(), equalTo("test.txt"));
    }
    {
      TimestampToken timestampToken = signedDocumentValidator.getDetachedTimestamps().get(1);
      assertThat(timestampToken.getDSSIdAsString(), equalTo(container.getTimestamps().get(1).getUniqueId()));
      assertThat(timestampToken.getFileName(), equalTo("META-INF/timestamp002.tst"));
      assertThat(timestampToken.getTimestampScopes(), hasSize(3));
      assertThat(timestampToken.getTimestampScopes().get(0).getDocumentName(), equalTo("META-INF/ASiCArchiveManifest.xml"));
      assertThat(timestampToken.getTimestampScopes().get(1).getDocumentName(), equalTo("META-INF/timestamp.tst"));
      assertThat(timestampToken.getTimestampScopes().get(2).getDocumentName(), equalTo("test.txt"));
    }
    XmlDiagnosticData diagnosticData = signedDocumentValidator.getDiagnosticData();
    assertThat(diagnosticData.getContainerInfo().getContainerType(), sameInstance(expectedContainerType));
    assertThat(diagnosticData.getContainerInfo().getManifestFiles(), hasSize(1));
    assertThat(diagnosticData.getContainerInfo().getManifestFiles().get(0).getFilename(),
            equalTo("META-INF/ASiCArchiveManifest.xml"));
    assertThat(diagnosticData.getContainerInfo().getContentFiles(), contains("test.txt"));
  }

  @Override
  protected CadesValidationDssFacade getDefaultCadesDssFacade() {
    CadesValidationDssFacade cadesValidationDssFacade = new CadesValidationDssFacade();
    configureAiaSourceAndCertificateSource(cadesValidationDssFacade);
    return cadesValidationDssFacade;
  }

}
