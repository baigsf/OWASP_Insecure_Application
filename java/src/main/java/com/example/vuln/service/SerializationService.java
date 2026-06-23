package com.example.vuln.service;

import com.thoughtworks.xstream.XStream;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.*;

@Service
public class SerializationService {

    // VULNERABILITY: Insecure Java deserialization
    public Object deserializeJava(byte[] data) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // VULNERABILITY: Insecure deserialization from Base64
    public Object deserializeBase64(String base64) throws IOException, ClassNotFoundException {
        byte[] data = java.util.Base64.getDecoder().decode(base64);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // VULNERABILITY: XStream deserialization without type filtering
    public Object deserializeXstream(String xml) {
        XStream xstream = new XStream();
        return xstream.fromXML(xml);
    }

    // VULNERABILITY: SnakeYAML deserialization of untrusted data
    public Object parseYamlUnsafe(String yaml) {
        Yaml y = new Yaml();
        return y.load(yaml);
    }

    // VULNERABILITY: Insecure Java serialization to file
    public void serializeToFile(Object obj, String filename) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename));
        oos.writeObject(obj);
        oos.close();
    }
}
