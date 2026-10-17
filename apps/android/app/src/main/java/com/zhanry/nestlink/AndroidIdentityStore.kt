package com.zhanry.nestlink

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class IdentityMaterial(val deviceId: String, val seed: ByteArray)

internal class AndroidIdentityStore(
    context: Context,
    prefsName: String = "nestlink_identity_v1",
    private val alias: String = "nestlink.installation.identity.v1",
) {
    private val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)

    @Synchronized
    fun loadOrCreate(): IdentityMaterial {
        val ciphertext = prefs.getString("seed_ciphertext", null)
        val deviceId = prefs.getString("device_id", null)
        if (ciphertext != null || deviceId != null) {
            require(ciphertext != null && deviceId != null) { "Android identity storage is incomplete" }
            val encrypted = Base64.decode(ciphertext, Base64.NO_WRAP)
            require(encrypted.size > 12 + 16) { "Android identity storage is invalid" }
            val nonce = encrypted.copyOfRange(0, 12)
            val body = encrypted.copyOfRange(12, encrypted.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, nonce))
            cipher.updateAAD(deviceId.toByteArray(Charsets.UTF_8))
            val seed = cipher.doFinal(body)
            require(seed.size == 32) { seed.fill(0); "Android identity seed has the wrong size" }
            require(runCatching { UUID.fromString(deviceId).toString() == deviceId }.getOrDefault(false)) {
                seed.fill(0)
                "Android identity identifier is invalid"
            }
            return IdentityMaterial(deviceId, seed)
        }

        val seed = ByteArray(32).also(SecureRandom()::nextBytes)
        val id = UUID.randomUUID().toString()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(id.toByteArray(Charsets.UTF_8))
            val sealed = cipher.doFinal(seed)
            val combined = cipher.iv + sealed
            val committed = prefs.edit()
                .putString("seed_ciphertext", Base64.encodeToString(combined, Base64.NO_WRAP))
                .putString("device_id", id)
                .commit()
            combined.fill(0)
            require(committed) { "Android identity storage could not be saved" }
            return IdentityMaterial(id, seed)
        } catch (failure: Throwable) {
            seed.fill(0)
            throw failure
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }
}
