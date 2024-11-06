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

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.exceptions.IllegalContainerContentException;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.digidoc4j.test.util.TestZipUtil.createDeflatedEntry;
import static org.digidoc4j.test.util.TestZipUtil.createStoredEntry;
import static org.digidoc4j.test.util.TestZipUtil.writeEntriesToByteArray;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

public class AsicSContainerParsingTest extends AbstractTest {

  @Test
  public void openContainer_WhenAsicsContainsSignatureAndTimestamp_ThrowsIllegalContainerContentException() {
    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(
                    "src/test/resources/testFiles/invalid-containers/1xTST-and-XAdES-signature.asics",
                    configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("ASiC-S container cannot contain signatures and timestamp tokens simultaneously")
    );
  }

  @Test
  public void openContainer_WhenAsicsContainsCadesLtSignature_ThrowsIllegalContainerContentException() {
    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(
                    "src/test/resources/testFiles/invalid-containers/CAdES-baseline-lt.asics",
                    configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: META-INF/signature.p7s")
    );
  }

  @Test
  public void openContainer_WhenAsicsContainsCadesLtaSignature_ThrowsIllegalContainerContentException() {
    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(
                    "src/test/resources/testFiles/invalid-containers/CAdES-baseline-lta.asics",
                    configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: META-INF/signature.p7s")
    );
  }

  @Test
  public void openContainer_WhenAsicsContainsAsiceStyleCadesLtSignature_ThrowsIllegalContainerContentException() {
    IllegalContainerContentException caughtException = assertThrows(
                IllegalContainerContentException.class,
                () -> ContainerOpener.open(
                        "src/test/resources/testFiles/invalid-containers/CAdES-baseline-lt-for-ASiC-E.asics",
                        configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: META-INF/signature001.p7s")
    );
  }

  @Test
  public void openContainer_WhenAsicsContainsAsiceStyleCadesLtaSignatureWithDetachedTimestamp_ThrowsIllegalContainerContentException() {
    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(
                    "src/test/resources/testFiles/invalid-containers/CAdES-baseline-lta-for-ASiC-E.asics",
                    configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: META-INF/signature001.p7s")
    );
  }

  @Test
  public void openContainer_WhenUnsignedAsicsContainsMultipleDataFiles_ThrowsIllegalContainerContentException() {
    byte[] containerBytes = writeEntriesToByteArray(
            createStoredEntry(ASiCUtils.MIME_TYPE, MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry("datafile-1", "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry("datafile-2", "unused".getBytes(StandardCharsets.UTF_8))
    );

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(new ByteArrayInputStream(containerBytes), configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("ASiC-S container cannot contain more than one datafile")
    );
  }

  @Test
  public void openContainer_WhenAsicsContainsCadesSignature_ThrowsIllegalContainerContentException() {
    openContainer_WhenAsicsContainsCadesSignature_ThrowsIllegalContainerContentException("signature.p7s");
  }

  @Test
  public void openContainer_WhenAsicsContainsCadesSignatureUpperCase_ThrowsIllegalContainerContentException() {
    openContainer_WhenAsicsContainsCadesSignature_ThrowsIllegalContainerContentException("SIGNATURE.P7S");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openContainer_WhenAsicsContainsCadesSignature_ThrowsIllegalContainerContentException(String entryName) {
    byte[] containerBytes = writeEntriesToByteArray(
            createStoredEntry(ASiCUtils.MIME_TYPE, MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + entryName, "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry("datafile", "unused".getBytes(StandardCharsets.UTF_8))
    );

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(new ByteArrayInputStream(containerBytes), configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
  }

  @Test
  public void openContainer_WhenAsicsContainsEvidenceRecordErs_ThrowsIllegalContainerContentException() {
    openContainer_WhenAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("evidencerecord.ers");
  }

  @Test
  public void openContainer_WhenAsicsContainsEvidenceRecordErsUpperCase_ThrowsIllegalContainerContentException() {
    openContainer_WhenAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("EVIDENCERECORD.ERS");
  }

  @Test
  public void openContainer_WhenAsicsContainsEvidenceRecordXml_ThrowsIllegalContainerContentException() {
    openContainer_WhenAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("evidencerecord.xml");
  }

  @Test
  public void openContainer_WhenAsicsContainsEvidenceRecordXmlUpperCase_ThrowsIllegalContainerContentException() {
    openContainer_WhenAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("EVIDENCERECORD.XML");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openContainer_WhenAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException(String entryName) {
    byte[] containerBytes = writeEntriesToByteArray(
            createStoredEntry(ASiCUtils.MIME_TYPE, MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + entryName, "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry("datafile", "unused".getBytes(StandardCharsets.UTF_8))
    );

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(new ByteArrayInputStream(containerBytes), configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported evidence record entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
