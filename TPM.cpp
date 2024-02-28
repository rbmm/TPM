HRESULT TpmSealUnseal(_Out_ PBYTE* ppbOutput, 
					  _Out_ ULONG* pcbOutput,
					  _In_ BOOLEAN bEncrypt,
					  _In_ NCRYPT_KEY_HANDLE hKey, 
					  _In_ const BYTE* pbInput, 
					  _In_ ULONG cbInput,
					  _In_opt_ PCSTR pcszPin = 0)
{
	PVOID pPaddingInfo = 0;

	if (pcszPin)
	{
		BCryptBuffer bc_buff = { (ULONG)strlen(pcszPin), NCRYPTBUFFER_TPM_SEAL_PASSWORD, const_cast<PSTR>(pcszPin) };
		BCryptBufferDesc bc_desc = { BCRYPTBUFFER_VERSION, 1, &bc_buff };

		pPaddingInfo = &bc_desc;
	}

	HRESULT hr;

	PBYTE pb = 0;
	ULONG cb = 0;
	while (NOERROR == (hr = (bEncrypt ? NCryptEncrypt : NCryptDecrypt)(hKey, 
		const_cast<PBYTE>(pbInput), cbInput, pPaddingInfo, pb, cb, &cb, NCRYPT_SEALING_FLAG)))
	{
		if (pb)
		{
			*ppbOutput = pb, *pcbOutput = cb, pb = 0;
			break;
		}

		if (!(pb = (PBYTE)LocalAlloc(LMEM_FIXED, cb)))
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			break;
		}
	}

	if (pb)
	{
		LocalFree(pb);
	}

	return hr;
}

HRESULT CryptSealUnseal(_Out_ PBYTE* ppbOutput, 
						_Out_ ULONG* pcbOutput,
						_In_ BOOLEAN bEncrypt,
						_In_ const BYTE* pbInput, 
						_In_ ULONG cbInput,
						_In_opt_ PCSTR pcszPin = 0)
{
	DATA_BLOB DataOut{}, DataIn { cbInput, const_cast<PBYTE>(pbInput) };

	DATA_BLOB* pOptionalEntropy = 0;

	if (pcszPin)
	{
		DATA_BLOB Entropy = { (ULONG)strlen(pcszPin), (PBYTE)pcszPin };
		pOptionalEntropy = &Entropy;
	}

	HRESULT hr = (bEncrypt 
		? CryptProtectData(&DataIn, 0, pOptionalEntropy, 0, 0, CRYPTPROTECT_LOCAL_MACHINE, &DataOut) 
		: CryptUnprotectData(&DataIn, 0, pOptionalEntropy, 0, 0, CRYPTPROTECT_LOCAL_MACHINE, &DataOut))
		? S_OK : HRESULT_FROM_WIN32(GetLastError());

	*ppbOutput = DataOut.pbData, *pcbOutput = DataOut.cbData;

	return hr;
}

HRESULT SealUnseal(_Out_ PBYTE *ppbOutput, 
				   _Out_ ULONG *pcbOutput,
				   _In_ BOOLEAN bEncrypt,
				   _In_ const BYTE* pbInput, 
				   _In_ ULONG cbInput,
				   _In_opt_ PCSTR pcszPin = 0)
{
	NCRYPT_KEY_HANDLE hKey;
	NCRYPT_PROV_HANDLE hProvider;

	NTSTATUS status;

	switch (status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0))
	{
	case NOERROR:

		status = NCryptOpenKey(hProvider, &hKey, TPM_RSA_SRK_SEAL_KEY, 0, NCRYPT_SILENT_FLAG);

		NCryptFreeObject(hProvider);

		if (NOERROR == status)
		{
			status = TpmSealUnseal(ppbOutput, pcbOutput, bEncrypt, hKey, pbInput, cbInput, pcszPin);
			NCryptFreeObject(hKey);
		}
		break;

	case NTE_FAIL:
	case NTE_DEVICE_NOT_READY:
		// no TPM
		status = CryptSealUnseal(ppbOutput, pcbOutput, bEncrypt, pbInput, cbInput, pcszPin);;
		break;
	}

	return status;
}

HRESULT CreateMasterKey(_In_ PCWSTR lpName, _In_opt_ PCSTR pcszPin = 0)
{
	UCHAR bSecret[0x20];

	HRESULT status = BCryptGenRandom(0, bSecret, sizeof(bSecret), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (0 <= status)
	{
		PBYTE pb;
		ULONG cb;
		if (NOERROR == (status = SealUnseal(&pb, &cb, TRUE, bSecret, sizeof(bSecret), pcszPin)))
		{
			status = SaveToFile(lpName, pb, cb);

			LocalFree(pb);
		}
	}

	return status;
}

HRESULT GenerateSymmetricKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PUCHAR pbSecret, _In_ ULONG cbSecret)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0)))
	{
		status = BCryptGenerateSymmetricKey(hAlgorithm, phKey, 0, 0, pbSecret, cbSecret, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT LoadMasterKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PCWSTR lpName, _In_opt_ PCSTR pcszPin = 0)
{
	PBYTE pb, pbSecret;
	ULONG cb;
	HRESULT status = ReadFromFile(lpName, &pb, &cb);

	if (S_OK == status)
	{
		status = SealUnseal(&pbSecret, &cb, FALSE, pb, cb, pcszPin);
		LocalFree(pb);

		if (S_OK == status)
		{
			status = GenerateSymmetricKey(phKey, pbSecret, cb);
			LocalFree(pbSecret);
		}
	}
	return status;
}

HRESULT TestTPM(_In_ PCSTR msg, _In_ PCWSTR lpName, _In_opt_ PCSTR pcszPin = 0)
{
	HRESULT status;
	if (S_OK == (status = CreateMasterKey(lpName, pcszPin)))
	{
		BCRYPT_KEY_HANDLE hKey;

		// encrypt
		if (S_OK == (status = LoadMasterKey(&hKey, lpName, pcszPin)))
		{
			PBYTE pbIn = (PBYTE)msg, pb = 0;
			ULONG cbIn = (ULONG)strlen(msg), cb = 0;

			while (0 <= (status = BCryptEncrypt(hKey, pbIn, cbIn, 0, 0, 0, pb, cb, &cb, BCRYPT_BLOCK_PADDING)))
			{
				if (pb)
				{
					break;
				}

				pb = (PBYTE)alloca(cb);
			}

			BCryptDestroyKey(hKey);

			if (0 <= status)
			{
				// decrypt
				if (S_OK == (status = LoadMasterKey(&hKey, lpName, pcszPin)))
				{
					if (0 <= (status = BCryptDecrypt(hKey, pb, cb, 0, 0, 0, pb, cb, &cb, BCRYPT_BLOCK_PADDING)))
					{
						status = cb == cbIn && !memcmp(msg, pb, cb) ? S_OK : NTE_FAIL;
					}
					BCryptDestroyKey(hKey);
				}
			}
		}
	}

	return status;
}