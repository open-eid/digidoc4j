package prototype;

import eu.europa.ec.markt.dss.TSLConstant;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

import java.util.Calendar;

/**
 * Mocking ServiceInfo
 */
public class MockServiceInfo extends ServiceInfo {

  public static final int FIFTEEN_YEARS_AGO = -15;

  /**
   * Mocking ServiceInfo
   */
  public MockServiceInfo() {

    setTspName("DSS, Mock Office DSS-CA");
    setType(TSLConstant.CA_QC);
    setServiceName("DSS, Mock Service Name");
    setStatus(TSLConstant.SERVICE_STATUS_UNDERSUPERVISION_119612);
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.YEAR, FIFTEEN_YEARS_AGO);
    setStatusStartDate(calendar.getTime());
    setStatusEndDate(null);
    setTlWellSigned(true);
  }
}
