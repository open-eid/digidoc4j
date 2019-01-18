package org.digidoc4j.impl;

import eu.europa.esig.dss.x509.CertificateToken;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.SignatureVerificationException;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class CommonOCSPSource extends SKOnlineOCSPSource {

  private final Logger LOGGER = LoggerFactory.getLogger(CommonOCSPSource.class);

  private boolean useAiaOcsp;
  private boolean useNonce = true;

  /**
   * @param configuration configuration
   */
  public CommonOCSPSource(Configuration configuration) {
    super(configuration);
  }

  @Override
  public String getAccessLocation(X509Certificate certificate) {
    if (getConfiguration().isAiaOcspPreferred()) {
      LOGGER.info("Trying to find AIA OCSP url for certificate <{}>", certificate.getSubjectDN().getName());
      String aiaOcspFromCertificate = getAccessLocationFromCertificate(certificate);
      if (!StringUtils.isEmpty(aiaOcspFromCertificate)) {
        LOGGER.info("Found AIA OCSP url from certificate");
        setAiaOCspParams(certificate);
        return aiaOcspFromCertificate;
      } else {
        LOGGER.info("Could not find OCSP url from certificate. Trying to Retrieve it from configuration");
        if (getConfiguration() != null) {
          String issuerCommonName = getCN(certificate.getIssuerX500Principal());
          String aiaOcspFromConfiguration = getConfiguration().getAiaOcspSourceByCN(issuerCommonName);
          if (!StringUtils.isEmpty(aiaOcspFromConfiguration)) {
            LOGGER.info("Found AIA OCSP url from configuration");
            setAiaOCspParams(certificate);
            return aiaOcspFromConfiguration;
          }
        }
        LOGGER.info("Could not find OCSP url configuration. Using default OCSP source");
        return super.getAccessLocation(certificate);
      }
    } else {
      return super.getAccessLocation(certificate);
    }
  }

  @Override
  public Extension createNonce(X509Certificate certificate) {
    if (!useNonce) {
      LOGGER.info("Given AIA OCSP should use no nonce, skipping creating nonce..");
      return null;
    }
    LOGGER.debug("Creating default OCSP nonce ...");
    return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(Helper.generateRandomBytes(32)));
  }

  @Override
  protected void verifyOcspResponderCertificate(CertificateToken token) {
    List<CertificateToken> tokens = getConfiguration().getTSL().get(token.getCertificate().getSubjectX500Principal());
    List<CertificateToken> tokensByIssuer = getConfiguration().getTSL().get(token.getCertificate().getIssuerX500Principal());
    if (CollectionUtils.isEmpty(tokens) && (!useAiaOcsp || CollectionUtils.isEmpty(tokensByIssuer))) {
      throw new SignatureVerificationException(String.format("OCSP response certificate <%s> match is not found in TSL", token.getDSSIdAsString()));
    }
    try {
      if (!token.getCertificate().getExtendedKeyUsage().contains(OID_OCSP_SIGNING)) {
        throw new SignatureVerificationException(String.format("OCSP response certificate <%s> does not have 'OCSPSigning' extended key usage", token.getDSSIdAsString()));
      }
    } catch (CertificateParsingException e) {
      throw new SignatureVerificationException(String.format("Error on verifying 'OCSPSigning' extended key usage for OCSP response certificate <%s>", token.getDSSIdAsString()), e);
    }
  }

  @Override
  protected void checkNonce(BasicOCSPResp response, Extension expectedNonceExtension) {
    if (!useNonce) {
      return;
    }
    super.checkNonce(response, expectedNonceExtension);
  }

  private String getAccessLocationFromCertificate(X509Certificate certificate) {
    LOGGER.info("Trying to retrieve OCSP url from the certificate");
    try {
      byte[] encodedAiaBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
      if (encodedAiaBytes != null) {
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(encodedAiaBytes));
        AccessDescription[] descriptions = aia.getAccessDescriptions();
        for (AccessDescription description : descriptions) {
          if (OCSPObjectIdentifiers.id_pkix_ocsp.getId().equals(description.getAccessMethod().getId())) {
            return description.getAccessLocation().getName().toString();
          }
        }
      }
    } catch (IOException e) {
      LOGGER.warn("Error reading ocsp location from certificate");
    }
    return null;
  }

  private String getCN(X500Principal x500Principal) {
    X500Name x500name = new X500Name(x500Principal.getName() );
    RDN cn = x500name.getRDNs(BCStyle.CN)[0];
    return IETFUtils.valueToString(cn.getFirst().getValue());
  }

  private void setAiaOCspParams(X509Certificate certificate) {
    useAiaOcsp = true;
    useNonce = getConfiguration().getUseNonceForAiaOcspByCN(getCN(certificate.getIssuerX500Principal()));
  }

}
