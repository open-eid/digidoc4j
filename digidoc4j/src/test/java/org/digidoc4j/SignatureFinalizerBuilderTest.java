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

import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.asice.AsicESignatureFinalizer;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SignatureFinalizerBuilderTest {

  @Test
  public void aFinalizer_WhenBDOCContainerIsProvided_ReturnsAsicESignatureFinalizer() {
    Container container = ContainerBuilder.aContainer(BDOC).build();
    SignatureParameters signatureParameters = new SignatureParameters();

    SignatureFinalizer result = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);

    assertThat(result, instanceOf(AsicESignatureFinalizer.class));
  }

  @Test
  public void aFinalizer_WhenASICEContainerIsProvided_ReturnsAsicESignatureFinalizer() {
    Container container = ContainerBuilder.aContainer(ASICE).build();
    SignatureParameters signatureParameters = new SignatureParameters();

    SignatureFinalizer result = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);

    assertThat(result, instanceOf(AsicESignatureFinalizer.class));
  }

  @Test
  public void aFinalizer_WhenASICSContainerIsProvided_ThrowsNotSupportedException() {
    Container container = ContainerBuilder.aContainer(ASICS).build();
    SignatureParameters signatureParameters = new SignatureParameters();

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> SignatureFinalizerBuilder.aFinalizer(container, signatureParameters)
    );

    assertThat(caughtException.getMessage(), containsString("Creation of ASiC-S signatures is not supported"));
  }

  @Test
  public void aFinalizer_WhenDDOCContainerIsProvided_ThrowsNotSupportedException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureParameters signatureParameters = new SignatureParameters();

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> SignatureFinalizerBuilder.aFinalizer(container, signatureParameters)
    );

    assertThat(caughtException.getMessage(), containsString("Creation of DDOC signatures is not supported"));
  }

  @Test
  public void aFinalizer_WhenDataFilesAreProvidedAndContainerTypeIsBDOC_ReturnsAsicESignatureFinalizer() {
    List<DataFile> dataFiles = new ArrayList<>();
    SignatureParameters signatureParameters = new SignatureParameters();
    Configuration configuration = Configuration.getInstance();

    SignatureFinalizer result = SignatureFinalizerBuilder
            .aFinalizer(dataFiles, signatureParameters, configuration, BDOC);

    assertThat(result, instanceOf(AsicESignatureFinalizer.class));
  }

  @Test
  public void aFinalizer_WhenDataFilesAreProvidedAndContainerTypeIsASICE_ReturnsAsicESignatureFinalizer() {
    List<DataFile> dataFiles = new ArrayList<>();
    SignatureParameters signatureParameters = new SignatureParameters();
    Configuration configuration = Configuration.getInstance();

    SignatureFinalizer result = SignatureFinalizerBuilder
            .aFinalizer(dataFiles, signatureParameters, configuration, ASICE);

    assertThat(result, instanceOf(AsicESignatureFinalizer.class));
  }

  @Test
  public void aFinalizer_WhenDataFilesAreProvidedAndContainerTypeIsASICS_ThrowsNotSupportedException() {
    List<DataFile> dataFiles = new ArrayList<>();
    SignatureParameters signatureParameters = new SignatureParameters();
    Configuration configuration = Configuration.getInstance();

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> SignatureFinalizerBuilder.aFinalizer(dataFiles, signatureParameters, configuration, ASICS)
    );

    assertThat(caughtException.getMessage(), containsString("Creation of ASiC-S signatures is not supported"));
  }

  @Test
  public void aFinalizer_WhenDataFilesAreProvidedAndContainerTypeIsDDOC_ReturnsAsicESignatureFinalizer() {
    List<DataFile> dataFiles = new ArrayList<>();
    SignatureParameters signatureParameters = new SignatureParameters();
    Configuration configuration = Configuration.getInstance();

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> SignatureFinalizerBuilder.aFinalizer(dataFiles, signatureParameters, configuration, DDOC)
    );

    assertThat(caughtException.getMessage(), containsString("Creation of DDOC signatures is not supported"));
  }

}
