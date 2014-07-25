package org.digidoc4j.utils;

import java.util.Date;

public final class DateUtils {

  private DateUtils() {

  }

  /**
   * Checks is date in range of sixty seconds
   *
   * @param date to compare
   * @return true if the date is within 60 seconds, otherwise false
   */
  public static boolean isAlmostNow(Date date) {
    return isInRangeOneMinute(new Date(), date);
  }

  private static boolean isInRangeOneMinute(Date date1, Date date2) {
    final int oneMinuteInSeconds = 60;
    Date latestTime = org.apache.commons.lang.time.DateUtils.addSeconds(date2, oneMinuteInSeconds);
    Date earliestTime = org.apache.commons.lang.time.DateUtils.addSeconds(date2, -oneMinuteInSeconds);
    return date1.before(latestTime) && date1.after(earliestTime);
  }
}
