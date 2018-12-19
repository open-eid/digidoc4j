/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.utils;

import static org.apache.commons.lang3.time.DateUtils.addSeconds;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Date utils
 */
public final class DateUtils {

  private static final Logger logger = LoggerFactory.getLogger(DateUtils.class);
  private static final String DEFAULT_DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
  private static final String GREENWICH_MEAN_TIME = "Etc/GMT";

  private DateUtils() {
  }

  /**
   * Checks is date in range of sixty seconds
   *
   * @param date to compare
   * @return true if the date is within 60 seconds, otherwise false
   */
  public static boolean isAlmostNow(Date date) {
    boolean inRange = isInRangeOneMinute(new Date(), date);
    logger.debug("Is almost now: " + inRange);
    return inRange;
  }

  private static boolean isInRangeOneMinute(Date date1, Date date2) {
    final int oneMinuteInSeconds = 60;
    return isInRangeSeconds(date1, date2, oneMinuteInSeconds);
  }

  public static boolean isInRangeMinutes(Date date1, Date date2, int rangeInMinutes) {
    int rangeInSeconds = rangeInMinutes * 60;
    return isInRangeSeconds(date1, date2, rangeInSeconds);
  }

  public static long differenceInMinutes(Date date1, Date date2) {
    return TimeUnit.MILLISECONDS.toMinutes(Math.abs(date1.getTime() - date2.getTime()));
  }

  private static boolean isInRangeSeconds(Date date1, Date date2, int rangeInSeconds) {
    Date latestTime = addSeconds(date2, rangeInSeconds);
    Date earliestTime = addSeconds(date2, -rangeInSeconds);
    return date1.before(latestTime) && date1.after(earliestTime);
  }

  /**
   * Get Date Formatted with GMT Zone
   *
   * @return SimpleDateFormat
   */
  public static SimpleDateFormat getDateFormatterWithGMTZone() {
    SimpleDateFormat sdf = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT);
    sdf.setTimeZone(TimeZone.getTimeZone(GREENWICH_MEAN_TIME));
    return sdf;
  }
}
