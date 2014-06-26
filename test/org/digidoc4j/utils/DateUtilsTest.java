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
  public void testIsAlmostNowComparedTo4SecondsBeforeNow() throws Exception {
    Date nowMinus10Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), -4);
    assertTrue(DateUtils.isAlmostNow(nowMinus10Seconds));
  }

  @Test
  public void testIsAlmostNowComparedTo4SecondsAfterNow() throws Exception {
    Date nowPlus10Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), 4);
    assertTrue(DateUtils.isAlmostNow(nowPlus10Seconds));
  }

  @Test
  public void testIsAlmostNowComparedTo40SecondsBeforeNow() throws Exception {
    Date nowMinus40Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), -40);
    assertFalse(DateUtils.isAlmostNow(nowMinus40Seconds));
  }

  @Test
  public void testIsAlmostNowComparedTo40SecondsAfterNow() throws Exception {
    Date nowPlus40Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), 40);
    assertFalse(DateUtils.isAlmostNow(nowPlus40Seconds));
  }
}