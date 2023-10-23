/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.TSLRefreshCallback;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.TslRefreshException;
import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.test.TestAssert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@RunWith(MockitoJUnitRunner.class)
public class TslRefreshCallbackInteractionTest extends AbstractTest {

  @Mock
  private TSLRefreshCallback tslRefreshCallback;

  @Override
  protected void before() {
    configuration = ConfigurationSingeltonHolder.getInstance();
    configuration.setTslRefreshCallback(tslRefreshCallback);
  }

  @Test
  public void testCallbackReturnsTrueOnManualRefresh() {
    mockEnsureTSLState(true);
    configuration.getTSL().refresh();
    configuration.getTSL().refresh();

    verifyCallbackCalled(2);
  }

  @Test
  public void testCallbackReturnsFalseOnManualRefresh() {
    mockEnsureTSLState(false);
    configuration.getTSL().refresh();

    mockEnsureTSLState(true);
    configuration.getTSL().refresh();

    verifyCallbackCalled(2);
  }

  @Test
  public void testCallbackThrowsExceptionOnManualRefresh() {
    TslRefreshException exceptionToThrow = new TslRefreshException("Exception message");
    mockEnsureTSLState(exceptionToThrow);

    TslRefreshException caughtException = assertThrows(
            TslRefreshException.class,
            () -> configuration.getTSL().refresh()
    );

    mockEnsureTSLState(true);
    configuration.getTSL().refresh();

    assertEquals("Exception message", caughtException.getMessage());
    verifyCallbackCalled(2);
  }

  @Test
  public void testCallbackReturnsTrueOnOpeningAndValidatingContainer() {
    mockEnsureTSLState(true);

    Container container = ContainerOpener.open(ASICE_WITH_TS_SIG);
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);

    verifyCallbackCalled(1);
  }

  @Test
  public void testCallbackReturnsFalseOnOpeningAndValidatingContainer() {
    mockEnsureTSLState(false);

    Container container = ContainerOpener.open(ASICE_WITH_TS_SIG);
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);

    Mockito.verify(tslRefreshCallback, Mockito.atLeastOnce()).ensureTSLState(Mockito.any(TLValidationJobSummary.class));
    Mockito.verifyNoMoreInteractions(tslRefreshCallback);
  }

  @Test
  public void testCallbackThrowsExceptionOnOpeningContainer() {
    TslRefreshException exceptionToThrow = new TslRefreshException("Exception message");
    mockEnsureTSLState(exceptionToThrow);

    TslRefreshException caughtException = assertThrows(
            TslRefreshException.class,
            () -> ContainerOpener.open(ASICE_WITH_TS_SIG)
    );

    assertEquals("Exception message", caughtException.getMessage());
    verifyCallbackCalled(1);
  }

  @Test
  public void testCallbackThrowsExceptionOnValidatingContainer() {
    mockEnsureTSLState(false);
    Container container = ContainerOpener.open(ASICE_WITH_TS_SIG);
    Mockito.reset(tslRefreshCallback);

    TslRefreshException exceptionToThrow = new TslRefreshException("Exception message");
    mockEnsureTSLState(exceptionToThrow);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> container.validate()
    );

    assertEquals("Error validating signatures on multiple threads: Exception message", caughtException.getMessage());
    verifyCallbackCalled(1);
  }

  @Test
  public void testCallbackReturnsTrueOnCreatingAndSigningContainer() {
    mockEnsureTSLState(true);

    Container container = createContainerBy(Container.DocumentType.ASICE,
            createTextDataFile("test.txt", "Test")
    );
    createSignatureBy(container, pkcs12Esteid2018SignatureToken);

    verifyCallbackCalled(1);
  }

  @Test
  public void testCallbackReturnsFalseOnCreatingAndSigningContainer() {
    mockEnsureTSLState(false);

    Container container = createContainerBy(Container.DocumentType.ASICE,
            createTextDataFile("test.txt", "Test")
    );
    createSignatureBy(container, pkcs12Esteid2018SignatureToken);

    Mockito.verify(tslRefreshCallback, Mockito.atLeastOnce()).ensureTSLState(Mockito.any(TLValidationJobSummary.class));
    Mockito.verifyNoMoreInteractions(tslRefreshCallback);
  }

  @Test
  public void testCallbackThrowsExceptionOnSigningContainer() {
    TslRefreshException exceptionToThrow = new TslRefreshException("Exception message");
    mockEnsureTSLState(exceptionToThrow);

    Container container = createContainerBy(Container.DocumentType.ASICE,
            createTextDataFile("test.txt", "Test")
    );
    TslRefreshException caughtException = assertThrows(
            TslRefreshException.class,
            () -> createSignatureBy(container, pkcs12Esteid2018SignatureToken)
    );

    assertEquals("Exception message", caughtException.getMessage());
    verifyCallbackCalled(1);
  }

  private void mockEnsureTSLState(boolean toBeReturned) {
    Mockito.doReturn(toBeReturned).when(tslRefreshCallback).ensureTSLState(Mockito.any(TLValidationJobSummary.class));
  }

  private void mockEnsureTSLState(Throwable toBeThrown) {
    Mockito.doThrow(toBeThrown).when(tslRefreshCallback).ensureTSLState(Mockito.any(TLValidationJobSummary.class));
  }

  private void verifyCallbackCalled(int wantedNumberOfInvocations) {
    Mockito.verify(tslRefreshCallback, Mockito.times(wantedNumberOfInvocations)).ensureTSLState(Mockito.any(TLValidationJobSummary.class));
    Mockito.verifyNoMoreInteractions(tslRefreshCallback);
  }

}
