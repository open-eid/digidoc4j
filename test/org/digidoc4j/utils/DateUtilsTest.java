package org.digidoc4j.utils;

import java.util.Date;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DateUtilsTest {

  @Test
  public void testIsAlmostNowComparedToNow() throws Exception {
    assertTrue(DateUtils.isAlmostNow(new Date()));
  }

  @Test
  public void testIsAlmostNowComparedTo10SecondsBeforeNow() throws Exception {
    Date nowMinus10Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), -1);
    assertTrue(DateUtils.isAlmostNow(nowMinus10Seconds));
  }

  @Test
  public void testIsAlmostNowComparedTo10SecondsAfterNow() throws Exception {
    Date nowMinus10Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), 1);
    assertTrue(DateUtils.isAlmostNow(nowMinus10Seconds));
  }

  @Test
  public void testIsAlmostNowComparedTo40SecondsBeforeNow() throws Exception {
    Date nowMinus10Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), -6);
    assertFalse(DateUtils.isAlmostNow(nowMinus10Seconds));
  }

  @Test
  public void testIsAlmostNowComparedTo40SecondsAfterNow() throws Exception {
    Date nowMinus10Seconds = org.apache.commons.lang.time.DateUtils.addSeconds(new Date(), 6);
    assertFalse(DateUtils.isAlmostNow(nowMinus10Seconds));
  }
}