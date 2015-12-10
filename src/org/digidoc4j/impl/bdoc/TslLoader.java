/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.File;
import java.io.Serializable;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.Protocol;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TslLoader implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(TslLoader.class);
  protected static final File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir") + "/digidoc4jTSLCache");
  private boolean checkSignature = true;
  private String tslLocation;
  private File tslKeystoreFile;
  private String tslKeyStorePassword;
  private Integer connectionTimeout;

  public TslLoader(String tslLocation, File tslKeystoreFile, String tslKeyStorePassword) {
    this.tslKeystoreFile = tslKeystoreFile;
    this.tslKeyStorePassword = tslKeyStorePassword;
    this.tslLocation = tslLocation;
  }

  public TSLCertificateSource createTSL() {
    try {
      TSLCertificateSource tslCertificateSource = new TSLCertificateSource(this);
      TSLRepository tslRepository = new TSLRepository();
      tslRepository.setTrustedListsCertificateSource(tslCertificateSource);

      TSLValidationJob tslValidationJob = new TSLValidationJob();
      DataLoader dataLoader = createDataLoader();
      tslValidationJob.setDataLoader(dataLoader);
      KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(tslKeystoreFile, tslKeyStorePassword);
      tslValidationJob.setDssKeyStore(keyStoreCertificateSource);
      tslValidationJob.setLotlUrl(tslLocation);
      tslValidationJob.setLotlCode("EU");
      tslValidationJob.setRepository(tslRepository);
      tslValidationJob.setCheckLOTLSignature(checkSignature);
      tslValidationJob.setCheckTSLSignatures(checkSignature);

      tslValidationJob.refresh();

      return tslCertificateSource;
    } catch (DSSException e) {
      logger.error("Unable to load TSL: " + e.getMessage());
      throw new TslCertificateSourceInitializationException(e.getMessage());
    }
  }

  public void invalidateCache() {
    try {
      FileUtils.cleanDirectory(fileCacheDirectory);
    } catch (Exception e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  public void refresh() {
    //TODO
  }

  public void setConnectionTimeout(Integer connectionTimeout) {
    this.connectionTimeout = connectionTimeout;
  }

  public void setCheckSignature(boolean checkSignature) {
    this.checkSignature = checkSignature;
  }

  private DataLoader createDataLoader() {
    if (Protocol.isHttpUrl(tslLocation)) {
      FileCacheDataLoader dataLoader = new FileCacheDataLoader();
      if(connectionTimeout != null) {
        dataLoader.setTimeoutConnection(connectionTimeout);
      }
      dataLoader.setFileCacheDirectory(fileCacheDirectory);
      return dataLoader;
    } else {
      return new CommonsDataLoader();
    }
  }
}
