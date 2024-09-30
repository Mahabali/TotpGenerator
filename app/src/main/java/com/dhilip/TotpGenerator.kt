package com.dhilip
// Peace for everyone
import org.apache.commons.codec.binary.Base32
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

public class TOTPGenerator {

    private var OTP_LENGTH = 6
    private val RADIX = 10
    private val HMAC_KEY_TYPE = "RAW"
    private val TIME_DIVISOR = 1000
    private val BYTE_MASK = 0xFF
    private val BYTE_OFFSET_MASK = 0xF
    private val OTP_BIT_MASK = 0x7F
    private val SHIFT_24 = 24
    private val SHIFT_16 = 16
    private val SHIFT_8 = 8

    sealed class Algorithm(val algorithmName: String) {
         object SHA1 : Algorithm("HmacSHA1")
         object SHA256 : Algorithm("HmacSHA256")
         object SHA384 : Algorithm("HmacSHA384")
         object SHA512 : Algorithm("HmacSHA512")
    }
    // Default OTP Length is 6
    // Time period is in seconds
    public fun generateTOTP(base32Secret: String, algorithm: Algorithm, period: Int, otpLength: Int = 6): String {
        if (otpLength < 1) {
            throw RuntimeException("Invalid otp length")
        }
        if (base32Secret.isNullOrEmpty()) {
            throw RuntimeException("Invalid secret")
        }
        if (period < 1) {
            throw RuntimeException("Invalid time period in seconds")
        }
        OTP_LENGTH = otpLength
        val currentTimeSeconds = System.currentTimeMillis() / TIME_DIVISOR
        val counter = currentTimeSeconds / period
        return generateTOTPInternal(base32Secret, counter, algorithm)
    }

    private fun generateTOTPInternal(secret: String, counter: Long, algorithm: Algorithm): String {
        val decodedKey = Base32().decode(secret)
        val hash: ByteArray = try {
            val mac = Mac.getInstance(algorithm.algorithmName)
            val keySpec = SecretKeySpec(decodedKey, HMAC_KEY_TYPE)
            mac.init(keySpec)
            val data = createCounterData(counter)
            mac.doFinal(data)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Invalid algorithm: $algorithm", e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Invalid key: $secret", e)
        }

        val otp = extractOTPFromHash(hash)
        return otp.toString().padStart(OTP_LENGTH, '0')
    }

    private fun createCounterData(counter: Long): ByteArray {
        val data = ByteArray(8)
        var value = counter
        for (i in 7 downTo 0) {
            data[i] = (value and BYTE_MASK.toLong()).toByte()
            value = value shr SHIFT_8
        }
        return data
    }

    private fun extractOTPFromHash(hash: ByteArray): Int {
        val offset = hash[hash.size - 1].toInt() and BYTE_OFFSET_MASK
        val binary = ((hash[offset].toInt() and OTP_BIT_MASK) shl SHIFT_24) or
                ((hash[offset + 1].toInt() and BYTE_MASK) shl SHIFT_16) or
                ((hash[offset + 2].toInt() and BYTE_MASK) shl SHIFT_8) or
                (hash[offset + 3].toInt() and BYTE_MASK)
        return binary % Math.pow(RADIX.toDouble(), OTP_LENGTH.toDouble()).toInt()
    }
}