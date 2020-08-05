package svkreml.extractKey;

import java.util.Objects;
import java.util.function.Supplier;

public final class Lazy<T> {

    private final Supplier<T> supplier;
    private volatile T value;

    public Lazy(Supplier<T> supplier) {
        this.supplier = supplier;
    }

    public T get() {
        return value == null ? compute(supplier) : value;
    }

    private synchronized T compute(Supplier<T> supplier) {
        if (value == null) {
            value = Objects.requireNonNull(supplier.get());
        }
        return value;
    }
}
