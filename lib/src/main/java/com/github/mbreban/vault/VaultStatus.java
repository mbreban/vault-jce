package com.github.mbreban.vault;

public class VaultStatus {

    Boolean initialized;
    Boolean sealed;
    String version;

    private VaultStatus(Builder builder) {
        this.initialized = builder.initialized;
        this.sealed = builder.sealed;
        this.version = builder.version;
    }

    public Boolean isInitialized() {
        return initialized;
    }

    public Boolean isSealed() {
        return sealed;
    }

    public String getVersion() {
        return version;
    }

    public static class Builder {

        Boolean initialized;
        Boolean sealed;
        String version;

        public Builder setInitialized(Boolean initialized) {
            this.initialized = initialized;
            return this;
        }

        public Builder setSealed(Boolean sealed) {
            this.sealed = sealed;
            return this;
        }

        public Builder setVersion(String version) {
            this.version = version;
            return this;
        }

        public VaultStatus build() {
            return new VaultStatus(this);
        }
    }

}
