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

import org.junit.Test;

import java.util.Date;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DateUtilsTest {

  @Test
  public void testIsAlmostNowComparedToNow() throws Exception {
    assertTrue(DateUtils.isAlmostNow(new Date()));
  }

  @Test
  public void testIsAlmostNowComparedToOneSecondsBeforeNow() throws Exception {
    Date nowMinusOneSecond = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), -1);
    assertTrue(DateUtils.isAlmostNow(nowMinusOneSecond));
  }

  @Test
  public void testIsAlmostNowComparedToOneSecondsAfterNow() throws Exception {
    Date nowPlusOneSecond = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), 1);
    assertTrue(DateUtils.isAlmostNow(nowPlusOneSecond));
  }

  @Test
  public void testIsAlmostNowComparedToOneMInuteBeforeNow() throws Exception {
    assertFalse(DateUtils.isAlmostNow(org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), -61)));
  }

  @Test
  public void testIsAlmostNowComparedToOneMinuteAfterNow() throws Exception {
    assertFalse(DateUtils.isAlmostNow(org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), 61)));
  }
}
