package org.digidoc4j.impl;

import java.util.Date;

import org.bouncycastle.cert.ocsp.SingleResp;
import org.digidoc4j.exceptions.NotSupportedException;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class DefaultOCSPToken extends OCSPToken {

  @Override
  public void extractInfo() {
    if (this.getBasicOCSPResp() != null) {
      this.productionDate = this.getBasicOCSPResp().getProducedAt();
      this.signatureAlgorithm = SignatureAlgorithm.forOID(this.getBasicOCSPResp().getSignatureAlgOID().getId());
      SingleResp bestSingleResp = this.getBestSingleResp();
      if (bestSingleResp != null) {
        this.thisUpdate = bestSingleResp.getThisUpdate();
        this.nextUpdate = bestSingleResp.getNextUpdate();
        //this.extractStatusInfo(bestSingleResp);
      }
    }
  }

  private SingleResp getBestSingleResp() {
    Date lastUpdated = null;
    SingleResp singleResponseMatch = null;
    for (SingleResp singleResponse : this.getBasicOCSPResp().getResponses()) {
      if (DSSRevocationUtils.matches(this.getCertId(), singleResponse)) {
        Date currentResponseUpdated = singleResponse.getThisUpdate();
        if (lastUpdated == null || currentResponseUpdated.after(lastUpdated)) {
          singleResponseMatch = singleResponse;
          lastUpdated = currentResponseUpdated;
        }
      }
    }
    return singleResponseMatch;
  }

  @Override
  public Date getArchiveCutOff() {
    throw new NotSupportedException("Information not extracted");
  }

}
