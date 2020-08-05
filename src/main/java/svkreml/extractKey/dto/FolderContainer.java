package svkreml.extractKey.dto;

import lombok.Getter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

@Getter
public class FolderContainer extends Container {

    String folder;

    public FolderContainer(String folder, String pin) {
        super(pin);
        this.folder = folder;
    }

    @Override
    protected Data LoadContainerData() {
        try {
            return new Data(
                    Files.readAllBytes(Paths.get(folder, "header.key")),
                    Files.readAllBytes(Paths.get(folder, "masks.key")),
                    Files.readAllBytes(Paths.get(folder, "masks2.key")),
                    Files.readAllBytes(Paths.get(folder, "name.key")),
                    Files.readAllBytes(Paths.get(folder, "primary.key")),
                    Files.readAllBytes(Paths.get(folder, "primary2.key"))
            );
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }
}
