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

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.digidoc4j.Container;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;

/**
 * Abstract base class of facade classes for DSS functionality related to ASiC containers.
 */
public abstract class AbstractCadesDssFacade {

  protected final CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();

  /**
   * Configures this facade to use the specified {@link AIASource} for processing.
   *
   * @param aiaSource an instance of {@link AIASource} to use
   */
  public void setAiaSource(AIASource aiaSource) {
        certificateVerifier.setAIASource(aiaSource);
    }

  /**
   * Configures this facade to use the specified {@link CertificateSource} as a trusted certificate source.
   *
   * @param certificateSource an instance of {@link CertificateSource} to use
   */
  public void setCertificateSource(CertificateSource certificateSource) {
    if (certificateSource == null || certificateSource instanceof ListCertificateSource) {
      certificateVerifier.setTrustedCertSources((ListCertificateSource) certificateSource);
    } else {
      certificateVerifier.setTrustedCertSources(certificateSource);
    }
  }

  /**
   * Configures this facade to handle the contents of the specified container type.
   * Supported container types:
   * <ul>
   *     <li>{@link Container.DocumentType#ASICE}</li>
   *     <li>{@link Container.DocumentType#ASICS}</li>
   * </ul>
   *
   * @param type container type to use
   */
  public void setContainerType(Container.DocumentType type) {
    switch (type) {
      case ASICE:
        setContainerType(ASiCContainerType.ASiC_E, MimeTypeEnum.ASICE);
        break;
      case ASICS:
        setContainerType(ASiCContainerType.ASiC_S, MimeTypeEnum.ASICS);
        break;
      default:
        throw new NotSupportedException("Unsupported container type: " + type.name());
    }
  }

  /**
   * Configures this facade to use the specified ASiC container type and container mimetype.
   *
   * @param containerType ASiC container type to be configured
   * @param mimeType container mimetype to be configured
   */
  protected abstract void setContainerType(ASiCContainerType containerType, MimeType mimeType);

}
