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
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class SigningOcspSourceFactoryTest extends AbstractTest {

  @Test
  public void testCreateReturnsResultProvidedByFactoryFromConfigurationIfSet() {
    OCSPSource mockOCSPSource = Mockito.mock(OCSPSource.class);
    OCSPSourceFactory mockSigningOcspSourceFactory = Mockito.mock(OCSPSourceFactory.class);
    Mockito.doReturn(mockOCSPSource).when(mockSigningOcspSourceFactory).create();

    configuration.setSigningOcspSourceFactory(mockSigningOcspSourceFactory);
    OCSPSource ocspSource = new SigningOcspSourceFactory(configuration).create();
    Assert.assertSame(mockOCSPSource, ocspSource);

    Mockito.verify(mockSigningOcspSourceFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockSigningOcspSourceFactory, mockOCSPSource);
  }

  @Test
  public void testCreateReturnsDefaultImplIfFactoryUnsetInConfiguration() {
    OCSPSource ocspSource = new SigningOcspSourceFactory(configuration).create();

    Assert.assertNotNull(ocspSource);
    Assert.assertEquals(CommonOCSPSource.class, ocspSource.getClass());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
