package svkreml.extractKey;

import lombok.extern.slf4j.Slf4j;

import java.io.*;

/*
 * маленький класс для работы с файлами
 * */
@Slf4j
public class FileManager {
    public static byte[] read(String file) throws IOException {
        return read(new File(file));
    }


    public static byte[] read(File file) throws IOException {
        log.trace("чтение файла " + file.getAbsolutePath());
        FileInputStream fis;
        try {
            fis = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException("File not found: " + file.getAbsolutePath());
        }
        int size = fis.available();
        byte[] bytes = new byte[size];
        if (fis.read(bytes) < 0)
            throw new IOException("input stream is empty");
        log.trace("файл прочитан, " + bytes.length + " байт");
        return bytes;
    }

    public static void write(String file, byte[] bytes) throws IOException {
        write(new File(file), bytes, false);
    }

    public static void write(File file, byte[] bytes) throws IOException {
        write(file, bytes, false);
    }


    public static void writeWithDir(String file, byte[] bytes) throws IOException {
        write(new File(file), bytes, true);
    }

    public static void writeWithDir(File file, byte[] bytes) throws IOException {
        write(file, bytes, true);
    }

    public static void write(File file, byte[] bytes, boolean createDirs) throws IOException {
        if (createDirs) {
            File parent = file.getAbsoluteFile().getParentFile();
            if (!parent.exists()) {
                boolean mkdirs = parent.mkdirs();
            }
        }
        log.trace("запись в файл " + file.getAbsolutePath());
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.flush();
        fos.close();
        log.trace("файл записан, " + bytes.length + " байт");
    }
}
