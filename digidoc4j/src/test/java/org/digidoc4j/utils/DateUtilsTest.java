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

import java.time.Instant;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

public class DateUtilsTest {

  @Test
  public void testIsAlmostNowComparedToNow() throws Exception {
    Assert.assertTrue(DateUtils.isAlmostNow(new Date()));
  }

  @Test
  public void testIsAlmostNowComparedToOneSecondsBeforeNow() throws Exception {
    Date nowMinusOneSecond = org.apache.commons.lang3.time.DateUtils.addSeconds(new Date(), -1);
    Assert.assertTrue(DateUtils.isAlmostNow(nowMinusOneSecond));
  }

  @Test
  public void testIsAlmostNowComparedToOneSecondsAfterNow() throws Exception {
    Date nowPlusOneSecond = org.apache.commons.lang3.time.DateUtils.addSeconds(new Date(), 1);
    Assert.assertTrue(DateUtils.isAlmostNow(nowPlusOneSecond));
  }

  @Test
  public void testIsAlmostNowComparedToOneMInuteBeforeNow() throws Exception {
    Assert.assertFalse(DateUtils.isAlmostNow(org.apache.commons.lang3.time.DateUtils.addSeconds(new Date(), -61)));
  }

  @Test
  public void testIsAlmostNowComparedToOneMinuteAfterNow() throws Exception {
    Assert.assertFalse(DateUtils.isAlmostNow(org.apache.commons.lang3.time.DateUtils.addSeconds(new Date(), 61)));
  }

  @Test
  public void testRangeNotIn10Min() throws Exception {
    int range10min = 10;
    Date date100MinInFuture = org.apache.commons.lang3.time.DateUtils.addMinutes(new Date(), 100);
    Assert.assertFalse(DateUtils.isInRangeMinutes(new Date(), date100MinInFuture, range10min));
  }

  @Test
  public void testRangeNotIn10MinSwitched() throws Exception {
    int range10min = 10;
    Date date100MinInFuture = org.apache.commons.lang3.time.DateUtils.addMinutes(new Date(), 100);
    Assert.assertFalse(DateUtils.isInRangeMinutes(date100MinInFuture, new Date(), range10min));
  }

  @Test
  public void testRangeIn10Min() throws Exception {
    int range10min = 10;
    Date date5MinInFuture = org.apache.commons.lang3.time.DateUtils.addMinutes(new Date(), 5);
    Assert.assertTrue(DateUtils.isInRangeMinutes(new Date(), date5MinInFuture, range10min));
  }

  @Test
  public void testRangeIn10MinWithFuture() throws Exception {
    int range10min = 10;
    Date date5MinInFuture = org.apache.commons.lang3.time.DateUtils.addMinutes(new Date(), 5);
    Assert.assertTrue(DateUtils.isInRangeMinutes(date5MinInFuture, new Date(), range10min));
  }

  @Test
  public void testRangeIn10MinWithPast() throws Exception {
    int range10min = 10;
    Date date5MinInPast = org.apache.commons.lang3.time.DateUtils.addMinutes(new Date(), -5);
    Assert.assertTrue(DateUtils.isInRangeMinutes(date5MinInPast, new Date(), range10min));
  }

  @Test
  public void testRangeIn5MinWithPastSwitched() throws Exception {
    int range10min = 10;
    Date date5MinInPast = org.apache.commons.lang3.time.DateUtils.addMinutes(new Date(), -5);
    Assert.assertTrue(DateUtils.isInRangeMinutes(new Date(), date5MinInPast, range10min));
  }

  @Test
  public void testDatesWithSecondPrecisionAreEqual() {
    Instant instant = Instant.ofEpochSecond(123_456_789L);
    Assert.assertEquals(0L, instant.getNano());
    Assert.assertEquals(0, DateUtils.compareAtSamePrecision(Date.from(instant), Date.from(instant)));
  }

  @Test
  public void testDatesWithMillisecondPrecisionAreEqual() {
    Instant instant = Instant.ofEpochMilli(123_456_789_123L);
    Assert.assertEquals(123_000_000L, instant.getNano());
    Assert.assertEquals(0, DateUtils.compareAtSamePrecision(Date.from(instant), Date.from(instant)));
  }

  @Test
  public void testDatesWithSecondPrecisionAreNotEqual() {
    Instant instant1 = Instant.ofEpochSecond(123_001L);
    Instant instant2 = Instant.ofEpochSecond(123_002L);
    Assert.assertTrue(DateUtils.compareAtSamePrecision(Date.from(instant1), Date.from(instant2)) < 0);
  }

  @Test
  public void testDatesWithMillisecondPrecisionAreNotEqualIfSecondsDiffer() {
    Instant instant1 = Instant.ofEpochMilli(123_001_999L);
    Instant instant2 = Instant.ofEpochMilli(123_002_999L);
    Assert.assertTrue(DateUtils.compareAtSamePrecision(Date.from(instant1), Date.from(instant2)) < 0);
  }

  @Test
  public void testDatesWithMillisecondPrecisionAreNotEqualIfMillisecondsDiffer() {
    Instant instant1 = Instant.ofEpochMilli(123_000_002L);
    Instant instant2 = Instant.ofEpochMilli(123_000_001L);
    Assert.assertTrue(DateUtils.compareAtSamePrecision(Date.from(instant1), Date.from(instant2)) > 0);
  }

  @Test
  public void testDatesWithSecondAndMillisecondPrecisionAreEqualIfEverythingUpToSecondPrecisionIsEqual() {
    Instant instant1 = Instant.ofEpochSecond(123_456_789L);
    Instant instant2 = Instant.ofEpochSecond(123_456_789L, 999_999_999L);
    Assert.assertEquals(0, DateUtils.compareAtSamePrecision(Date.from(instant1), Date.from(instant2)));
  }

}
