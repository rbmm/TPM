# TPM
 Easy encrypt/decrypt data with TPM


with TPM exist special, well known Key for sealing, TPM_RSA_SRK_SEAL_KEY or L"MICROSOFT_PCP_KSP_RSA_SEAL_KEY_3BD1C4BF-004E-4E2F-8A4D-0BF633DCB074"

we can open this key via NCryptOpenKey and than use it in calls NCryptEncrypt and NCryptDecrypt with NCRYPT_SEALING_FLAG

if NCryptOpenStorageProvider for MS_PLATFORM_KEY_STORAGE_PROVIDER return NTE_DEVICE_NOT_READY this probably mean that TPM not supported on machine

we also can use optional password for protect data, with NCRYPTBUFFER_TPM_SEAL_PASSWORD BCryptBuffer type 

of course only relative small data size can be encrypted/decrypted this way (up to 0x400 bytes). but we cangenerate random 32 bytes for example and encrypt/decrypt it
and than create from it AES256 key and use it for actual data encrypt/decrypt
