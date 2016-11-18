/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.dataloader;

import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.bdoc.SkDataLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;

/**
 * Manages the creation of data loaders for getting TimeStamp responses.
 */
public class TimeStampDataLoaderFactory implements DataLoaderFactory {

  private static final Logger logger = LoggerFactory.getLogger(TimeStampDataLoaderFactory.class);
  private Configuration configuration;
  private SignatureProfile signatureProfile;

  public TimeStampDataLoaderFactory(Configuration configuration, SignatureProfile signatureProfile) {
    this.configuration = configuration;
    this.signatureProfile = signatureProfile;
  }

  @Override
  public DataLoader create() {
    if (configuration.getTimestampDataLoaderFactory() == null) {
      return createDataLoader();
    } else {
      logger.debug("Using custom Timestamp data loader factory provided by the configuration");
      return configuration.getTimestampDataLoaderFactory().create();
    }
  }

  protected DataLoader createDataLoader() {
    logger.debug("Creating Timestamp data loader");
    SkDataLoader dataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(signatureProfile);
    return dataLoader;
  }
}
