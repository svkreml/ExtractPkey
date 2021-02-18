package svkreml.extractKey.dto;

import org.testng.Assert;
import org.testng.annotations.Test;
import svkreml.extractKey.PrivateKeyExport;

import java.io.IOException;

public class FullTest {
    @Test
    public void test() throws IOException {

        String pathToConteinerFolder = "00000000.000";
        String pincode = "123456";
        Container container = new FolderContainer(pathToConteinerFolder, pincode);
        new PrivateKeyExport().Export(container, System.out);
        Assert.assertEquals(true,true);
    }
}
