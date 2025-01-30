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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.IllegalTimestampException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.cades.CadesTimestamp;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@RunWith(MockitoJUnitRunner.class)
public class AsicSTimestampsValidationReportGeneratorTest extends AbstractTest {

  @Mock
  private AsicSContainer asicsContainer;
  @Mock
  private DSSDocument dataFileDocument;
  @Mock
  private DataFile dataFile;

  private AsicSTimestampsValidationReportGenerator validationReportGenerator;

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    doReturn(configuration).when(asicsContainer).getConfiguration();
    validationReportGenerator = new AsicSTimestampsValidationReportGenerator(asicsContainer);
    doReturn(Collections.singletonList(dataFile)).when(asicsContainer).getDataFiles();
    doReturn(dataFileDocument).when(dataFile).getDocument();
  }

  @Test
  public void openValidationReport_WhenTimestampTokenIsNotParsable_ThrowsIllegalTimestampException() {
    CadesTimestamp unparsableCadesTimestamp = new CadesTimestamp(
            new InMemoryDocument("Not a timestamp token content".getBytes(StandardCharsets.UTF_8))
    );
    Timestamp timestamp = new AsicSContainerTimestamp(unparsableCadesTimestamp);
    doReturn(Collections.singletonList(timestamp)).when(asicsContainer).getTimestamps();

    IllegalTimestampException caughtException = assertThrows(
            IllegalTimestampException.class,
            validationReportGenerator::openValidationReport
    );

    assertThat(caughtException.getMessage(), equalTo("Invalid timestamp token"));
    assertThat(caughtException.getCause(), instanceOf(TechnicalException.class));
    assertThat(caughtException.getCause().getMessage(), equalTo("Failed to parse TimeStampToken"));
    verify(asicsContainer).getTimestamps();
    verifyContainerInteractions();
  }

  @Test
  public void openValidationReport_WhenTimestampManifestIsNotParsable_ThrowsIllegalTimestampException() {
    CadesTimestamp validCadesTimestamp = new CadesTimestamp(
            new FileDocument("src/test/resources/testFiles/tst/timestamp.tst")
    );
    AsicArchiveManifest unparsableArchiveManifest = new AsicArchiveManifest(
            new InMemoryDocument("Not an ASiCArchiveManifest content".getBytes(StandardCharsets.UTF_8), "ASiCArchiveManifest.xml")
    );
    Timestamp timestamp = new AsicSContainerTimestamp(validCadesTimestamp, unparsableArchiveManifest);
    doReturn(Collections.singletonList(timestamp)).when(asicsContainer).getTimestamps();

    IllegalTimestampException caughtException = assertThrows(
            IllegalTimestampException.class,
            validationReportGenerator::openValidationReport
    );

    assertThat(caughtException.getMessage(), equalTo("Invalid manifest file"));
    assertThat(caughtException.getCause(), instanceOf(TechnicalException.class));
    assertThat(caughtException.getCause().getMessage(), equalTo("Failed to parse manifest file: ASiCArchiveManifest.xml"));
    verify(asicsContainer).getTimestamps();
    verifyContainerInteractions();
  }

  private void verifyContainerInteractions() {
    verify(asicsContainer).getConfiguration();
    verify(asicsContainer).getDataFiles();
    verify(dataFile).getDocument();
    verifyNoMoreInteractions(asicsContainer, dataFile);
    verifyNoInteractions(dataFileDocument);
  }

}
