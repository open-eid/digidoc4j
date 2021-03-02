package org.digidoc4j.impl.asic;

import org.digidoc4j.Configuration;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class EntryValidatorTest {

  @Test(expected = Test.None.class)
  public void emptyInput() throws IOException {
    ByteArrayInputStream inputStream = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));
    AsicStreamContainerParser containerParser = new AsicStreamContainerParser(inputStream, Configuration.of(Configuration.Mode.TEST));
    containerParser.parseContainer();
    AsicStreamContainerParser.EntryValidator validator = containerParser.new EntryValidator();
    validator.validate(0);
  }

  @Test(expected = IOException.class)
  public void emptyZipEntriesAndBigInput() throws IOException {
    ByteArrayInputStream inputStream = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));
    AsicStreamContainerParser containerParser = new AsicStreamContainerParser(inputStream, Configuration.of(Configuration.Mode.TEST));
    AsicStreamContainerParser.EntryValidator validator = containerParser.new EntryValidator();
    validator.validate(1000001);
  }

  @Test(expected = Test.None.class)
  public void potentialBloatingButNotExceedingMinimumThreshold() throws IOException {
    ByteArrayInputStream inputStream = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));
    AsicStreamContainerParser containerParser = new AsicStreamContainerParser(inputStream, Configuration.of(Configuration.Mode.TEST));
    AsicStreamContainerParser.EntryValidator validator = containerParser.new EntryValidator();
    validator.validate(1000000);
  }

  @Test(expected = Test.None.class)
  public void normalZipContainer() throws IOException {
    FileInputStream inputStream = new FileInputStream("src/test/resources/testFiles/valid-containers/valid-asice.asice");
    AsicStreamContainerParser containerParser = new AsicStreamContainerParser(inputStream, Configuration.of(Configuration.Mode.TEST));
    containerParser.parseContainer();
  }

  @Test(expected = IOException.class)
  public void unCompressedInputTooBig() throws IOException {
    FileInputStream inputStream = new FileInputStream("src/test/resources/testFiles/valid-containers/valid-asice.asice");
    AsicStreamContainerParser containerParser = new AsicStreamContainerParser(inputStream, Configuration.of(Configuration.Mode.TEST));
    containerParser.parseContainer();
    AsicStreamContainerParser.EntryValidator validator = containerParser.new EntryValidator();
    validator.validate(1000001);
  }

}
