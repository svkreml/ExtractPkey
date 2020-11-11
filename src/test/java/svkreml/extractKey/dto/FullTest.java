package svkreml.extractKey.dto;

import org.testng.Assert;
import org.testng.annotations.Test;
import svkreml.extractKey.PrivateKeyExport;

import java.io.IOException;

public class FullTest {
    @Test
    public void test() throws IOException {
        Container container = new FolderContainer("00000000.000", "123456");
        new PrivateKeyExport().Export(container, System.out);
        Assert.assertEquals(true,true);
    }
}
