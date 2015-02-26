package org.digidoc4j.testutils;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class ApacheWireDecoderTest {
    private ApacheWireDecoder decoder = new ApacheWireDecoder();
    
    @Test
    public void sampleOcspResponse() {
        String input =
            "0[0x82][0x2]U[\\n]\r\n" +
            "[0x1][0x0][0xa0][0x82][0x2]N0[0x82][0x2]J[0x6][0x9]+[0x6][0x1][0x5][0x5][0x7]0[0x1][0x1][0x4][0x82][0x2];0[0x82][0x2]70[0x82][0x1][0x1f][0xa1][0x81][0x86]0[0x81][0x83]1[0xb]0[0x9][0x6][0x3]U[0x4][0x6][0x13][0x2]EE1\"0 [0x6][0x3]U[0x4][\\n]\r\n" +
            "[0xc][0x19]AS Sertifitseerimiskeskus1[\\r]0[0xb][0x6][0x3]U[0x4][0xb][0xc][0x4]OCSP1'0%[0x6][0x3]U[0x4][0x3][0xc][0x1e]TEST of SK OCSP RESPONDER 20111[0x18]0[0x16][0x6][0x9]*[0x86]H[0x86][0xf7][\\r][0x1][0x9][0x1][0x16][0x9]pki@sk.ee[0x18][0xf]20150205141553Z0`0^0I0[0x9][0x6][0x5]+[0xe][0x3][0x2][0x1a][0x5][0x0][0x4][0x14]S=;[0xc8][0xf5][0xb1][\\n]\r\n" +
            "[0xec][0xc3]|[0xb6]gW[0xbf][0xd9][0x98][0xae][0x93][0x3][0x89][0x4][0x14][0x12][0xf2]Z>[0xea]V[0x1c][0xbf][0xcd][0x6][0xac][0xf1][0xf1]%[0xc9][0xa9]K[0xd4][0x14][0x99][0x2][0x10]$[0xaf][0xec][0xeb][0x12]h[0xd0][0x2]T[0x17][0xf7][0x86][0xed]o[0x1]Y[0x82][0x0][0x18][0xf]20150205141553Z[0xa1]!0[0x1f]0[0x1d][0x6][0x9]+[0x6][0x1][0x5][0x5][0x7]0[0x1][0x2][0x1][0x1][0xff][0x4][\\r]14231457537820[\\r][0x6][0x9]*[0x86]H[0x86][0xf7][\\r][0x1][0x1][0x5][0x5][0x0][0x3][0x82][0x1][0x1][0x0][0xb8][0xf8][0xdb]=[0xae][0x17]6?jJf[0xdd][0x81][0x8f][0xe5]`[0xe6][0x8a]f[0xa9][0xc5][0xe1][0xbe]{[0xf2]A$[0xa4][0xf3][0xc9][0xdb][0xc2][0xc2][0x98]^[0xea][0x9a]?[0xa4][0xde][0xe4]}Y^[0xb3];-W/8[0x4][0x85][0x5][0xff]l[0xd6][0xb6][0x5][0x9b][0xab][0xb][0xbe]X|[0xe3][0x88][0xd4]r[0x86]2[0xf2]!)[0xfc]QJ[0xb5]X[0xb7][0xa3]%[0xdf][0x6][0xcd][0x9c][0xba]l[0x8b][0xf5]4Zya[0x0][0x97]=4[0x7]\"[0xc]6<[0xab]0[0xb8][0xe4][0xe9]I[0x1b][0xd1]$[0xb2]h[0x14][0xa7],4[0x14]@[0xc7][0xd1][0x3][0x11][0xa0][0xb7][0xc7][0x89][0xfc][0xb7][0x1f][0xac]4[0x82][0xd8][0xfb]G[0xb4]j[0x98]S3[0x0]P[0x8a][0xb7]#[0x9e]8[0xf1][0xe0][0xe1]~@[0xcd][0xb][0x8c][0x15].[0x81][0xb0]rV[0xe8][0x5]Q[0x9a]N[0xe6][0x3]$*[0xf2]B&6zn5kj[0xff].[0xcb][0x1f]6[0xa1]rV[0xe9][0xf0][0xf0][0xce]{ [0x17][0xaf][0xb5][0xbe][0x8][0xd2][0xc6][0x1e][0xe7]@[0x97]LH[0xb][0xad][0xce][0x85]g`[0x1b]i<[0xb5][0x88][0x17]^[0x8b][0xf6]5[0xed][0xa3] [0xcf][0xb6][0xed][0x94][0xa3][0xd4][0xa5][0xf6]r[0xd5]d[0x9c][0xdd][0x9b][0xa6]z[0xdf][0x80][0xa6][0x92][0xeb] [0xe7]c[0xaf]B|[0xe4][0xc2][0xe3]";

        byte[] result = decoder.decode(input);
        
        assertEquals(
                "308202550a0100a082024e3082024a06092b06010505073001010482023b308202373082011fa18186308183310b300906035504061302454531223020060355040a0c19415320536572746966697473656572696d69736b65736b7573310d300b060355040b0c044f4353503127302506035504030c1e54455354206f6620534b204f43535020524553504f4e44455220323031313118301606092a864886f70d0109011609706b6940736b2e6565180f32303135303230353134313535335a3060305e3049300906052b0e03021a05000414533d3bc8f5b10aecc37cb66757bfd998ae930389041412f25a3eea561cbfcd06acf1f125c9a94bd41499021024afeceb1268d0025417f786ed6f01598200180f32303135303230353134313535335aa121301f301d06092b06010505073001020101ff040d31343233313435373533373832300d06092a864886f70d01010505000382010100b8f8db3dae17363f6a4a66dd818fe560e68a66a9c5e1be7bf24124a4f3c9dbc2c2985eea9a3fa4dee47d595eb33b2d572f38048505ff6cd6b6059bab0bbe587ce388d4728632f22129fc514ab558b7a325df06cd9cba6c8bf5345a796100973d3407220c363cab30b8e4e9491bd124b26814a72c341440c7d10311a0b7c789fcb71fac3482d8fb47b46a98533300508ab7239e38f1e0e17e40cd0b8c152e81b07256e805519a4ee603242af24226367a6e356b6aff2ecb1f36a17256e9f0f0ce7b2017afb5be08d2c61ee740974c480badce8567601b693cb588175e8bf635eda320cfb6ed94a3d4a5f672d5649cdd9ba67adf80a692eb20e763af427ce4c2e3", 
                Hex.encodeHexString(result));
    }

    @Test
    public void testAllPossibleBytes() {
        String encoded = encodeWithApacheWire(new ByteArrayInputStream(allPossibleBytes()));
        byte[] decodedBack = decoder.decode(encoded);
        
        assertArrayEquals(allPossibleBytes(), decodedBack);
    }
    
    @Test
    public void nondeterministicEncodingDueToAnOpenBracket() {
        String encoded = encodeWithApacheWire(new ByteArrayInputStream(new byte[] {'['}));
        byte[] decodedBack = decoder.decode(encoded);
        
        assertArrayEquals(new byte[] {'['}, decodedBack);
    }
    
    @Test
    public void nondeterministicEncodingDueToAnOpenBracket_2() {
        String encoded = encodeWithApacheWire(new ByteArrayInputStream(new byte[] {'[', 'a'}));
        byte[] decodedBack = decoder.decode(encoded);
        
        assertArrayEquals(new byte[] {'[', 'a'}, decodedBack);
    }

    @Test
    public void nondeterministicEncodingDueToAnOpenBracket_3() {
        String encoded = encodeWithApacheWire(new ByteArrayInputStream(new byte[] {'[', '0', 'x', '1'}));
        byte[] decodedBack = decoder.decode(encoded);
        
        assertArrayEquals(new byte[] {'[', '0', 'x', '1'}, decodedBack);
    }

    @Test
    public void introducingAClosingBracketMeansAnEscapeSequence() {
        String encoded = encodeWithApacheWire(new ByteArrayInputStream(new byte[] {'[', '0', 'x', '1', ']'}));
        byte[] decodedBack = decoder.decode(encoded);
        
        assertArrayEquals(new byte[] {1}, decodedBack);
    }

    private static byte[] allPossibleBytes() {
        byte[] allPossibleBytes = new byte[256];
        for(int i = 0; i < allPossibleBytes.length; i++) {
            allPossibleBytes[i] = (byte) i;
        }
        return allPossibleBytes;
    }
    
    /**
     * This code is modeled after the code in Apache HTTP Client's  
     * class org.apache.http.impl.conn.Wire . (Apparently they 
     * intend to make that class package private in the future.)
     */
    private static String encodeWithApacheWire(InputStream instream) {
        String result = "";

        final StringBuilder buffer = new StringBuilder();
        int ch;
        try {
            while ((ch = instream.read()) != -1) {
                if (ch == 13) {
                    buffer.append("[\\r]");
                } else if (ch == 10) {
                    buffer.append("[\\n]");
                    result += buffer.toString() + "\r\n";
                    buffer.setLength(0);
                } else if ((ch < 32) || (ch > 127)) {
                    buffer.append("[0x");
                    buffer.append(Integer.toHexString(ch));
                    buffer.append("]");
                } else {
                    buffer.append((char) ch);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (buffer.length() > 0) {
            result += buffer.toString();
        }

        return result;
    }

}
