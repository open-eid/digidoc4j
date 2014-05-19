package ee.sk.digidoc4j.utils;

import org.apache.commons.codec.binary.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class PKCS12SignerTest {
  private static PKCS12Signer pkcs12Signer;

  @BeforeClass
  public static void setUp() {
    pkcs12Signer = new PKCS12Signer("signout.p12", "test");
  }

  @Test
  public void testGetPrivateKey() throws Exception {
    assertEquals("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChn9qVaA+x3RkDBrD5ujwfnreK" +
        "5/Nb+Nvo9Vg5OLMn3JKUoUhFX6A/q5lBUylK/CU/lNRTv/kicqnu1aCyAiW0XVYk8jrOI1wRbHey" +
        "BMq/5gVm/vbbRtMi/XGLkgMZ5UDxY0QZfmu8wlRJ8164zRNocuUJLLXWOB6vda2RRXC3Cix4TDvQ" +
        "wGmPrQQJ8dzDIJEkLS7NCLBTcndm7buQegRc043gKMjUmRhGZEzF4oJa4pMfXqeSa+PUtrNyNNNQ" +
        "aOwTH29R8aFfGU2xorVvxoUieNipyWMEz8BTUGwwIceapWi77loBV/VQfStXnQNu/s6BC04ss43O" +
        "6sK70MB1qlRZAgMBAAECggEAT81lGRY7gZ/gpKzeH0AERbyRdaWXdJcIxhq2B/LmCs2PFpIX5CEW" +
        "N7nbvvR31A1xutYajIuiUI77NvEGGj6TLV5UlYOA451z7Sp4Y06YaW4CxtsnOhfbUlB/iuF6ZIPc" +
        "sBNKYagZPCdbhPQElgy0A4OPcRtBYVduV0YsgCkgQU+clV93bCALpDkpU6EeeVys8bfBBtk7cLXe" +
        "TF3IBXykvXi4tFaVDKz8lTYvDt66clhxFNBo+0H2IL4RqZ4sQCfpi8Gpi0yr2kmGDGvYgTOM8sOF" +
        "sS2iHwPDIOOEY6RINHNBRuMpC1rmkOOK40qnmVfMrGAj3QpqSDeN6HVu/yqhAQKBgQDVCUbOCCsS" +
        "oyhBPvQXOTesmD1Y/jrqXwPm8J2t9gKYKZwGtuiKeBwkRRg1Bqo8KwD3WABWrIa/qqYm1/NFKQnW" +
        "GqILLIrvh9ZLL5U3vDyCdPovYZfhYQX5wPwEkmhAdVfgROzNoADQQEM5o8cokoxn+Uz24Fn6Xz5n" +
        "YYB8kBQnOQKBgQDCOERfUSzbibl6I0Dn2JHwFgWqEdd2ViQoskeBhE9LhpT7bKD2osmCGvSLdt2B" +
        "hVLYwbM4mu+9QdYdEoIgvx+n42eZ60ycMChOgwTKC2KYb2NE19vpin0rgYt7C3zpxPjOR83ZUii+" +
        "9mc2zPUKu2oN0/ZBfEozqmRO4nKSm+V2IQKBgFuGTMEfiUHMjvLZFQ0VK/IexdyB/NXMVGTXYybl" +
        "1l+BIONRmb5Ds/NxK+E8J88JurSJPjv+izW1HwT5Ki7AXtV5Q70BOf+GoG5U1wrG+Egj8YiBqTrO" +
        "8D5Ixv0/2UI4J7TWZ9Y/s5nEwhz1XA72RxQ0avh1krKaULkhjo31aHMhAoGAa6A8m0ljf0DhzIIO" +
        "rKvBq3a4qtb6PDReE0NABtCoFGU+19kJlcL9waBoVYSIGQclssIcK8kIAyuhmDiyba0bwLBur8fJ" +
        "i1/QZjmKhOAsQeav7u1jixZYaKx/+66RCQZDDiSSONSjibcH2UFYpRrYGVOVShKzF9Bbh69K6F2F" +
        "maECgYALiEqtS4gfy0t4iydbAGxzvAZPwlifgqqjYsm9XoI7U8wJItw5NgWV+c28yuibZd6tKolN" +
        "vLV5ywqxQ8t3IoMO/mwXFOgHCUErlefeL7y1SOGqTp2OtJnKSoF9y1GLmXiYi2A0i46EEOR6Hapj" +
        "qRRMT9z0gtZJviW0dhr/VUZXrA==",
        Base64.encodeBase64String(pkcs12Signer.getPrivateKey().getEncoded()));
  }

}
