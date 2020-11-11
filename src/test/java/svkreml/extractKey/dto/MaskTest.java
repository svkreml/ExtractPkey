package svkreml.extractKey.dto;


import org.bouncycastle.util.encoders.Hex;
import org.testng.Assert;
import org.testng.annotations.Test;
import svkreml.extractKey.FileManager;

import java.io.IOException;



class MaskTest {

    @Test
    public void test() throws IOException {
        Mask mask = new Mask(FileManager.read("00000000.000/masks.key"));

        Assert.assertEquals(mask.hMacKey, Hex.decode("f8a9124a"));
        Assert.assertEquals(mask.key, Hex.decode("aec144fb251d8d63f3053221ab8aed6021c331f1c354cf7c13bf5511858538c3"));
        Assert.assertEquals(mask.salt, Hex.decode("44d50824275a3e8f5892e7d5"));
    }

}
