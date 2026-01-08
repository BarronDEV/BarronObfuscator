package dev.barron.utils;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.util.Map;

/**
 * Custom ClassWriter that doesn't require all classes to be on the classpath
 * Falls back to java/lang/Object when common superclass cannot be determined
 */
public class SafeClassWriter extends ClassWriter {

    private final Map<String, ClassReader> classReaders;

    public SafeClassWriter(int flags, Map<String, ClassReader> classReaders) {
        super(flags);
        this.classReaders = classReaders;
    }

    public SafeClassWriter(ClassReader classReader, int flags, Map<String, ClassReader> classReaders) {
        super(classReader, flags);
        this.classReaders = classReaders;
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
        // Try to find common superclass using our loaded classes
        try {
            return super.getCommonSuperClass(type1, type2);
        } catch (Exception e) {
            // If we can't determine the common superclass, fall back to Object
            // This is safe because the JVM will verify and compute the correct frames at
            // runtime
            return "java/lang/Object";
        }
    }

    @Override
    protected ClassLoader getClassLoader() {
        // Use a custom class loader that can read from our class map
        return new ClassLoader(SafeClassWriter.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                String internalName = name.replace('.', '/');
                ClassReader reader = classReaders.get(internalName);
                if (reader != null) {
                    byte[] bytes = new byte[reader.b.length];
                    System.arraycopy(reader.b, 0, bytes, 0, bytes.length);
                    return defineClass(name, bytes, 0, bytes.length);
                }
                throw new ClassNotFoundException(name);
            }
        };
    }
}
