package com.github.mbreban.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class VaultProviderTest {

    @Test
    void testVaultProvider() {
        VaultProvider classUnderTest = new VaultProvider();
        assertEquals(classUnderTest.getName(), "VaultProvider");
    }
}
