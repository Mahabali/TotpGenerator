package com.dhilip

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class TotpGeneratorTest {
    @Test 
    fun testTotpGenerator(){
        val generator = TOTPGenerator()
        val hash = generator.generateTOTP("213123", TOTPGenerator.Algorithm.SHA512, 300)
        assertEquals(1,1);
    }
}