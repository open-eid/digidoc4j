/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.OCSPSourceFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

@ExtendWith(MockitoExtension.class)
class SigningOcspSourceFactoryTest extends AbstractTest {

  @Test
  void testCreateReturnsResultProvidedByFactoryFromConfigurationIfSet() {
    OCSPSource mockOCSPSource = Mockito.mock(OCSPSource.class);
    OCSPSourceFactory mockSigningOcspSourceFactory = Mockito.mock(OCSPSourceFactory.class);
    Mockito.doReturn(mockOCSPSource).when(mockSigningOcspSourceFactory).create();

    configuration.setSigningOcspSourceFactory(mockSigningOcspSourceFactory);
    OCSPSource ocspSource = new SigningOcspSourceFactory(configuration).create();
    assertSame(mockOCSPSource, ocspSource);

    Mockito.verify(mockSigningOcspSourceFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockSigningOcspSourceFactory, mockOCSPSource);
  }

  @Test
  void testCreateReturnsNullProvidedByFactoryFromConfigurationIfExplicitlyConfigured() {
    OCSPSourceFactory mockSigningOcspSourceFactory = Mockito.mock(OCSPSourceFactory.class);
    Mockito.doReturn(null).when(mockSigningOcspSourceFactory).create();

    configuration.setSigningOcspSourceFactory(mockSigningOcspSourceFactory);
    OCSPSource ocspSource = new SigningOcspSourceFactory(configuration).create();
    assertNull(ocspSource);

    Mockito.verify(mockSigningOcspSourceFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockSigningOcspSourceFactory);
  }

  @Test
  void testCreateReturnsDefaultImplIfFactoryUnsetInConfiguration() {
    OCSPSource ocspSource = new SigningOcspSourceFactory(configuration).create();

    assertNotNull(ocspSource);
    assertEquals(CommonOCSPSource.class, ocspSource.getClass());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
