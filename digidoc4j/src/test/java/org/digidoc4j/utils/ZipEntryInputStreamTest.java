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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.zip.ZipInputStream;

@RunWith(MockitoJUnitRunner.class)
public class ZipEntryInputStreamTest {

  @Mock
  private ZipInputStream zipInputStream;

  private ZipEntryInputStream zipEntryInputStream;

  @Before
  public void setUp() {
    zipEntryInputStream = new ZipEntryInputStream(zipInputStream, null);
    Mockito.verifyNoInteractions(zipInputStream);
  }

  @Test
  public void availableShouldDelegateToZipInputStreamAvailable() throws IOException {
    Mockito.doReturn(7).when(zipInputStream).available();

    int result = zipEntryInputStream.available();
    Assert.assertEquals(7, result);

    Mockito.verify(zipInputStream, Mockito.times(1)).available();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void availableShouldPassOnExceptionThrownByZipInputStreamAvailable() throws IOException {
    IOException ioException = new IOException("Some ZipInputStream exception");
    Mockito.doThrow(ioException).when(zipInputStream).available();

    IOException caughtException = Assert.assertThrows(
            IOException.class,
            () -> zipEntryInputStream.available()
    );

    Assert.assertSame(ioException, caughtException);
    Mockito.verify(zipInputStream, Mockito.times(1)).available();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void closeShouldDelegateToZipInputStreamCloseEntry() throws IOException {
    zipEntryInputStream.close();

    Mockito.verify(zipInputStream, Mockito.times(1)).closeEntry();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void closeShouldPassOnExceptionThrownByZipInputStreamAvailable() throws IOException {
    IOException ioException = new IOException("Some ZipInputStream exception");
    Mockito.doThrow(ioException).when(zipInputStream).closeEntry();

    IOException caughtException = Assert.assertThrows(
            IOException.class,
            () -> zipEntryInputStream.close()
    );

    Assert.assertSame(ioException, caughtException);
    Mockito.verify(zipInputStream, Mockito.times(1)).closeEntry();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void markShouldDelegateToZipInputStreamMark() {
    zipEntryInputStream.mark(7);

    Mockito.verify(zipInputStream, Mockito.times(1)).mark(7);
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void markSupportedShouldDelegateToZipInputStreamMarkSupported() throws IOException {
    Mockito.doReturn(true).when(zipInputStream).markSupported();

    boolean result = zipEntryInputStream.markSupported();

    Assert.assertTrue(result);
    Mockito.verify(zipInputStream, Mockito.times(1)).markSupported();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void readShouldDelegateToZipInputStreamRead() throws IOException {
    Mockito.doReturn(7).when(zipInputStream).read();

    int result = zipEntryInputStream.read();

    Assert.assertEquals(7, result);
    Mockito.verify(zipInputStream, Mockito.times(1)).read();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void readShouldPassOnExceptionThrownByZipInputStreamRead() throws IOException {
    IOException ioException = new IOException("Some ZipInputStream exception");
    Mockito.doThrow(ioException).when(zipInputStream).read();

    IOException caughtException = Assert.assertThrows(
            IOException.class,
            () -> zipEntryInputStream.read()
    );

    Assert.assertSame(ioException, caughtException);
    Mockito.verify(zipInputStream, Mockito.times(1)).read();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void readWithArrayShouldDelegateToZipInputStreamReadWithArray() throws IOException {
    Mockito.doReturn(7).when(zipInputStream).read(Mockito.any(byte[].class));
    byte[] arrayOfBytes = new byte[32];

    int result = zipEntryInputStream.read(arrayOfBytes);

    Assert.assertEquals(7, result);
    Mockito.verify(zipInputStream, Mockito.times(1)).read(arrayOfBytes);
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void readWithArrayShouldPassOnExceptionThrownByZipInputStreamReadWithArray() throws IOException {
    IOException ioException = new IOException("Some ZipInputStream exception");
    Mockito.doThrow(ioException).when(zipInputStream).read(Mockito.any(byte[].class));
    byte[] arrayOfBytes = new byte[32];

    IOException caughtException = Assert.assertThrows(
            IOException.class,
            () -> zipEntryInputStream.read(arrayOfBytes)
    );

    Assert.assertSame(ioException, caughtException);
    Mockito.verify(zipInputStream, Mockito.times(1)).read(arrayOfBytes);
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void readWithArrayAndBoundsShouldDelegateToZipInputStreamReadWithArrayAndBounds() throws IOException {
    Mockito.doReturn(7).when(zipInputStream).read(Mockito.any(byte[].class), Mockito.anyInt(), Mockito.anyInt());
    byte[] arrayOfBytes = new byte[32];

    int result = zipEntryInputStream.read(arrayOfBytes, 3, 9);

    Assert.assertEquals(7, result);
    Mockito.verify(zipInputStream, Mockito.times(1)).read(arrayOfBytes, 3, 9);
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void readWithArrayAndBoundsShouldPassOnExceptionThrownByZipInputStreamReadWithArrayAndBounds() throws IOException {
    IOException ioException = new IOException("Some ZipInputStream exception");
    Mockito.doThrow(ioException).when(zipInputStream).read(Mockito.any(byte[].class), Mockito.anyInt(), Mockito.anyInt());
    byte[] arrayOfBytes = new byte[32];

    IOException caughtException = Assert.assertThrows(
            IOException.class,
            () -> zipEntryInputStream.read(arrayOfBytes, 3, 9)
    );

    Assert.assertSame(ioException, caughtException);
    Mockito.verify(zipInputStream, Mockito.times(1)).read(arrayOfBytes, 3, 9);
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void resetShouldDelegateToZipInputStreamReset() throws IOException {
    zipEntryInputStream.reset();

    Mockito.verify(zipInputStream, Mockito.times(1)).reset();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void resetShouldPassOnExceptionThrownByZipInputStreamReset() throws IOException {
    IOException ioException = new IOException("Some ZipInputStream exception");
    Mockito.doThrow(ioException).when(zipInputStream).reset();

    IOException caughtException = Assert.assertThrows(
            IOException.class,
            () -> zipEntryInputStream.reset()
    );

    Assert.assertSame(ioException, caughtException);
    Mockito.verify(zipInputStream, Mockito.times(1)).reset();
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void skipShouldDelegateToZipInputStreamSkip() throws IOException {
    Mockito.doReturn(9L).when(zipInputStream).skip(Mockito.anyLong());

    long result = zipEntryInputStream.skip(13L);

    Assert.assertEquals(9L, result);
    Mockito.verify(zipInputStream, Mockito.times(1)).skip(13L);
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

  @Test
  public void skipShouldPassOnExceptionThrownByZipInputStreamSkip() throws IOException {
    IOException ioException = new IOException("Some ZipInputStream exception");
    Mockito.doThrow(ioException).when(zipInputStream).skip(13L);

    IOException caughtException = Assert.assertThrows(
            IOException.class,
            () -> zipEntryInputStream.skip(13L)
    );

    Assert.assertSame(ioException, caughtException);
    Mockito.verify(zipInputStream, Mockito.times(1)).skip(13L);
    Mockito.verifyNoMoreInteractions(zipInputStream);
  }

}