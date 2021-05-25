package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.enumerations.Indication;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.impl.AbstractContainerValidationResult;

/**
 * Created by Andrei on 27.11.2017.
 */
public class TimeStampContainerValidationResult extends AbstractContainerValidationResult implements ContainerValidationResult {

  private TimeStampToken timeStampToken;
  private String signedBy = "";
  private String signedTime = "";

  /**
   * Gets container indication (TOTAL_PASSED or TOTAL_FAILED)
   *
   * @return Indication
   */
  public Indication getIndication() {
    if (this.isValid()) {
      return Indication.TOTAL_PASSED;
    }
    return Indication.TOTAL_FAILED;
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected String getResultName() {
    return "Timestamp container";
  }

  /*
   * ACCESSORS
   */

  /**
   * Get TimeStamp Token.
   */
  public TimeStampToken getTimeStampToken() {
    return timeStampToken;
  }

  /**
   * Set TimeStamp Token.
   *
   * @param timeStampToken token
   */
  public void setTimeStampToken(TimeStampToken timeStampToken) {
    this.timeStampToken = timeStampToken;
  }

  /**
   * Get signed time.
   */
  public String getSignedTime() {
    return signedTime;
  }

  /**
   * Set signed time.
   *
   * @param signedTime signed time
   */
  public void setSignedTime(String signedTime) {
    this.signedTime = signedTime;
  }

  /**
   * Get signed by value.
   */
  public String getSignedBy() {
    return signedBy;
  }

  /**
   * Set signed by value.
   *
   * @param signedBy signed by
   */
  public void setSignedBy(String signedBy) {
    this.signedBy = signedBy;
  }

}
