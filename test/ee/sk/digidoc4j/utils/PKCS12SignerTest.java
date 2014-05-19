package ee.sk.digidoc4j.utils;

import com.sun.org.apache.xml.internal.security.utils.Base64;
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
    assertEquals("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChn9qVaA+x3RkDBrD5ujwfnreK\n" +
        "5/Nb+Nvo9Vg5OLMn3JKUoUhFX6A/q5lBUylK/CU/lNRTv/kicqnu1aCyAiW0XVYk8jrOI1wRbHey\n" +
        "BMq/5gVm/vbbRtMi/XGLkgMZ5UDxY0QZfmu8wlRJ8164zRNocuUJLLXWOB6vda2RRXC3Cix4TDvQ\n" +
        "wGmPrQQJ8dzDIJEkLS7NCLBTcndm7buQegRc043gKMjUmRhGZEzF4oJa4pMfXqeSa+PUtrNyNNNQ\n" +
        "aOwTH29R8aFfGU2xorVvxoUieNipyWMEz8BTUGwwIceapWi77loBV/VQfStXnQNu/s6BC04ss43O\n" +
        "6sK70MB1qlRZAgMBAAECggEAT81lGRY7gZ/gpKzeH0AERbyRdaWXdJcIxhq2B/LmCs2PFpIX5CEW\n" +
        "N7nbvvR31A1xutYajIuiUI77NvEGGj6TLV5UlYOA451z7Sp4Y06YaW4CxtsnOhfbUlB/iuF6ZIPc\n" +
        "sBNKYagZPCdbhPQElgy0A4OPcRtBYVduV0YsgCkgQU+clV93bCALpDkpU6EeeVys8bfBBtk7cLXe\n" +
        "TF3IBXykvXi4tFaVDKz8lTYvDt66clhxFNBo+0H2IL4RqZ4sQCfpi8Gpi0yr2kmGDGvYgTOM8sOF\n" +
        "sS2iHwPDIOOEY6RINHNBRuMpC1rmkOOK40qnmVfMrGAj3QpqSDeN6HVu/yqhAQKBgQDVCUbOCCsS\n" +
        "oyhBPvQXOTesmD1Y/jrqXwPm8J2t9gKYKZwGtuiKeBwkRRg1Bqo8KwD3WABWrIa/qqYm1/NFKQnW\n" +
        "GqILLIrvh9ZLL5U3vDyCdPovYZfhYQX5wPwEkmhAdVfgROzNoADQQEM5o8cokoxn+Uz24Fn6Xz5n\n" +
        "YYB8kBQnOQKBgQDCOERfUSzbibl6I0Dn2JHwFgWqEdd2ViQoskeBhE9LhpT7bKD2osmCGvSLdt2B\n" +
        "hVLYwbM4mu+9QdYdEoIgvx+n42eZ60ycMChOgwTKC2KYb2NE19vpin0rgYt7C3zpxPjOR83ZUii+\n" +
        "9mc2zPUKu2oN0/ZBfEozqmRO4nKSm+V2IQKBgFuGTMEfiUHMjvLZFQ0VK/IexdyB/NXMVGTXYybl\n" +
        "1l+BIONRmb5Ds/NxK+E8J88JurSJPjv+izW1HwT5Ki7AXtV5Q70BOf+GoG5U1wrG+Egj8YiBqTrO\n" +
        "8D5Ixv0/2UI4J7TWZ9Y/s5nEwhz1XA72RxQ0avh1krKaULkhjo31aHMhAoGAa6A8m0ljf0DhzIIO\n" +
        "rKvBq3a4qtb6PDReE0NABtCoFGU+19kJlcL9waBoVYSIGQclssIcK8kIAyuhmDiyba0bwLBur8fJ\n" +
        "i1/QZjmKhOAsQeav7u1jixZYaKx/+66RCQZDDiSSONSjibcH2UFYpRrYGVOVShKzF9Bbh69K6F2F\n" +
        "maECgYALiEqtS4gfy0t4iydbAGxzvAZPwlifgqqjYsm9XoI7U8wJItw5NgWV+c28yuibZd6tKolN\n" +
        "vLV5ywqxQ8t3IoMO/mwXFOgHCUErlefeL7y1SOGqTp2OtJnKSoF9y1GLmXiYi2A0i46EEOR6Hapj\n" +
        "qRRMT9z0gtZJviW0dhr/VUZXrA==",
        Base64.encode(pkcs12Signer.getPrivateKey().getEncoded()));
  }

}
