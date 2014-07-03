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
  public void testIsAlmostNowComparedToElevenSecondsBeforeNow() throws Exception {
    Date nowMinus11Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), -11);
    assertFalse(DateUtils.isAlmostNow(nowMinus11Seconds));
  }

  @Test
  public void testIsAlmostNowComparedToElevenSecondsAfterNow() throws Exception {
    Date nowPlus11Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), 11);
    assertFalse(DateUtils.isAlmostNow(nowPlus11Seconds));
  }
}