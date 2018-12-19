package org.digidoc4j;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.CommonOCSPCertificateSource;
import org.digidoc4j.impl.OCSPCertificateValidator;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * Builder for certificate validator. Currently only OCSP is supported
 * <p>
 * Created by Janar Rahumeel (CGI Estonia)
 */
public final class CertificateValidatorBuilder {

  private static final CertificateSource defaultCertificateSource = new CommonOCSPCertificateSource();

  static {
    try {
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }
    } catch (Exception e) {
      throw new DSSException("Certificate validator builder error", e);
    }
  }

  private Configuration configuration;
  private CertificateSource certificateSource;
  private OCSPSource ocspSource;

  /**
   * @return CertificateSource
   */
  public static ExtendedCertificateSource getDefaultCertificateSource() {
    return (ExtendedCertificateSource) CertificateValidatorBuilder.defaultCertificateSource;
  }

  /**
   * @param configuration configuration context
   * @return CertificateValidatorBuilder
   */
  public CertificateValidatorBuilder withConfiguration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  /**
   * @param ocspSource the source of OCSP
   * @return CertificateValidatorBuilder
   */
  public CertificateValidatorBuilder withOCSPSource(OCSPSource ocspSource) {
    this.ocspSource = ocspSource;
    return this;
  }

  /**
   * @param certificateSource the source of certificate
   * @return CertificateValidatorBuilder
   */
  public CertificateValidatorBuilder withIssuerCertificateSource(CertificateSource certificateSource) {
    this.certificateSource = certificateSource;
    return this;
  }

  /**
   * @return CertificateValidator
   */
  public CertificateValidator build() {
    if (this.configuration == null) {
      this.configuration = ConfigurationSingeltonHolder.getInstance();
    }
    if (this.certificateSource == null) {
      this.certificateSource = CertificateValidatorBuilder.defaultCertificateSource;
    }
    if (this.ocspSource == null) {
      this.ocspSource = OCSPSourceBuilder.defaultOCSPSource().withConfiguration(this.configuration).build();
    }
    return new OCSPCertificateValidator(this.configuration, this.certificateSource, this.ocspSource);
  }

}
