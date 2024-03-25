package shared;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class FileService {

    public static void insert(final String content, final String filename) {
        try (var writer = new BufferedWriter(new FileWriter(filename, true))) {
            writer.write(content);
            writer.newLine();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String get(final String filename) {
        final var content = new StringBuilder();
        try (var reader = new BufferedReader(new FileReader(filename))) {
            String line = "";
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return content.toString();
    }
}