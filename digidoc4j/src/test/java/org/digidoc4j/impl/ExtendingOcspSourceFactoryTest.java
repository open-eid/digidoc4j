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
import org.mockito.Mockito;

public class ExtendingOcspSourceFactoryTest extends AbstractTest {

  @Test
  public void testCreateReturnsResultProvidedByFactoryFromConfigurationIfSet() {
    OCSPSource mockOCSPSource = Mockito.mock(OCSPSource.class);
    OCSPSourceFactory mockExtendingOcspSourceFactory = Mockito.mock(OCSPSourceFactory.class);
    Mockito.doReturn(mockOCSPSource).when(mockExtendingOcspSourceFactory).create();

    configuration.setExtendingOcspSourceFactory(mockExtendingOcspSourceFactory);
    OCSPSource ocspSource = new ExtendingOcspSourceFactory(configuration).create();
    Assert.assertSame(mockOCSPSource, ocspSource);

    Mockito.verify(mockExtendingOcspSourceFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockExtendingOcspSourceFactory, mockOCSPSource);
  }

  @Test
  public void testCreateReturnsNullProvidedByFactoryFromConfigurationIfExplicitlyConfigured() {
    OCSPSourceFactory mockExtendingOcspSourceFactory = Mockito.mock(OCSPSourceFactory.class);
    Mockito.doReturn(null).when(mockExtendingOcspSourceFactory).create();

    configuration.setExtendingOcspSourceFactory(mockExtendingOcspSourceFactory);
    OCSPSource ocspSource = new ExtendingOcspSourceFactory(configuration).create();
    Assert.assertNull(ocspSource);

    Mockito.verify(mockExtendingOcspSourceFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockExtendingOcspSourceFactory);
  }

  @Test
  public void testCreateReturnsNullIfFactoryUnsetInConfiguration() {
    Assert.assertNull(new ExtendingOcspSourceFactory(Configuration.of(Configuration.Mode.TEST)).create());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }
}
